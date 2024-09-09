/*
 * Abode Alarm
 *
 * Copyright 2020 Jo Rhett.  All Rights Reserved
 * Copyright 2024 Eric Meddaugh.  All Rights Reserved
 * Started from Hubitat example driver code https://github.com/hubitat/HubitatPublic/tree/master/examples/drivers
 * Implementation inspired by https://github.com/MisterWil/abodepy
 *
 *  Licensed under the Apache License, Version 2.0 -- details in the LICENSE file in this repo
 *
 * Original code: https://github.com/jorhett/hubitat-abode
 *
 */

import java.security.GeneralSecurityException
import java.lang.reflect.UndeclaredThrowableException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.math.BigInteger

metadata {
  definition (
    name: 'Abode Alarm 2024',
    namespace: 'x86cpu',
    author: 'Jo Rhett/Eric Meddaugh',
    importUrl: 'https://raw.githubusercontent.com/x86cpu/hubitat-abode/master/drivers/AbodeAlarm.groovy',
  ) {
    capability 'Actuator'
    capability 'Refresh'
    command 'armAway'
    command 'armHome'
    command 'disarm'
    command 'logout'
    command 'login'
    attribute 'isLoggedIn', 'String'
    attribute 'gatewayMode', 'String'
    attribute 'gatewayTimeline', 'String'
    attribute 'lastResult', 'String'
  }

  preferences {
    if(showLogin != false) {
      input name: 'username', type: 'text',     title: 'Abode username',   required: true,  displayDuringSetup: true, description: '<em>Abode username</em>'
      input name: 'password', type: 'password', title: 'Abode password',   required: true,  displayDuringSetup: true, description: '<em>Abode password</em>'
      input name: 'mfa_used', type: 'bool',     title: 'Account uses MFA', required: true,  displayDuringSetup: true, description: '<em>Does this account use MFA?</em>', defaultValue: false
      input name: 'mfa_code', type: 'text',     title: 'Current MFA Code', required: false, displayDuringSetup: true, description: '<em>Not stored -- used one time</em>'
      input name: 'mfa_seed', type: 'text',     title: 'Current MFA Seed', required: false, displayDuringSetup: true, description: '<em>(not required, if used will auto login when logged out) -- stored plain text</em>'
    }

    input name: 'targetModeAway', type: 'enum',   title: 'Hubitat Mode when Abode Away',     options: location.getModes().collect { it.toString() }
    input name: 'targetModeHome', type: 'enum',   title: 'Hubitat Mode when Abode Home',     options: location.getModes().collect { it.toString() }
    input name: 'syncArming',     type: 'bool',   title: 'Sync Exit Delay start',            defaultValue: false, description: '<em>Enable concurrent exit delays</em>'

    input name: 'saveContacts',   type: 'bool',   title: 'Save Abode timeline events',       defaultValue: false, description: '<em>...to Hubitat Events</em>'
    input name: 'saveGeofence',   type: 'bool',   title: 'Save Abode geofence events',       defaultValue: false, description: '<em>...to Hubitat Events</em>'
    input name: 'saveAutomation', type: 'bool',   title: 'Save CUE Automation actions',      defaultValue: false, description: '<em>...to Hubitat Events</em>'
    input name: 'saveDevices',    type: 'bool',   title: 'Create child devices',             defaultValue: false, description: '<em>...to Hubitat Devices</em>'

    input name: 'showLogin',      type: 'bool',   title: 'Show login fields',                defaultValue: true,  description: '<em>Show login fields</em>', submitOnChange: true
    input name: 'logDebug',       type: 'bool',   title: 'Enable debug logging',             defaultValue: true,  description: '<em>for 2 hours</em>'
    input name: 'logTrace',       type: 'bool',   title: 'Enable trace logging',             defaultValue: false, description: '<em>for 30 minutes</em>'
    input name: 'logInfo',        type: 'bool',   title: 'Enable info logging',              defaultValue: true, description: '<em>until manually disabled</em>'
    input name: 'timeoutSlack',   type: 'number', title: 'Timeout slack in seconds',         defaultValue: '30',  description: '<em><b>+</b> for resilience, <b>-</b> reconnect faster</em>'
  }
}

// Hubitat standard methods
def installed() {
  log.debug 'installed'
  device.updateSetting('showLogin', [value: true, type: 'bool'])
  device.updateSetting('saveDevices', [value: false, type: 'bool'])
  initialize()
  if (!childDevices)
    createIsArmedSwitch()
}

private initialize() {
  state.uuid = UUID.randomUUID()
  state.cookies = [:]
}

def updated() {
  if (logInfo) log.info 'Preferences saved.'
  if (logInfo) log.info 'debug logging is: ' + logDebug
  if (logInfo) log.info 'description logging is: ' + logDetails
  if (logInfo) log.info 'Abode username: ' + username
  if (!childDevices)
    createIsArmedSwitch()

  // Disable high levels of logging after time
  if (logTrace) runIn(1800,disableTrace)
  if (logDebug) runIn(7200,disableDebug)

  // Reasons we should attempt login again
  if (
    // If they supplied mfa code they want to login again
    (!username.isEmpty() && !password.isEmpty() && mfa_code) ||
    // If we aren't logged in, attempt login
    (!username.isEmpty() && !password.isEmpty() && (state.token == null)) ||
    // If they changed the username, attempt login
    (!username.isEmpty() && !password.isEmpty() && (username != getDataValue('abodeID')))
  )
    login()
  else
    validateSession()

  // Clear the MFA token entry -- will be useless anyway
  device.updateSetting('mfa_code', [value: '', type: 'text'])
  createChildDevices()
  if (logDebug) {
    if ( !mfa_seed.isEmpty() ) state.HEX = base32_decode(mfa_seed)
    if ( !mfa_seed.isEmpty() ) state.MFA = generateTOTP1(mfa_seed)
  } else {
    state.remove("HEX")
    state.remove("MFA")
  }

}

def createChildDevices() {
  if (!saveDevices) {
    getChildDevices().each {
        if ( it.deviceNetworkId != device.id + '-isArmed' )
          deleteChildDevice(it.deviceNetworkId)
    }
  }
  if (saveDevices && saveContacts) {
    reply = doHttpRequest('GET','/api/v1/devices')
    cnt=0
    added=0
    while (reply[cnt] != null ) {
      if (logTrace) log.trace("reply[$cnt]: "+ reply[cnt])
      if (logTrace) log.trace("reply[$cnt][id]: "+ reply[cnt]['id'])
      if (logTrace) log.trace("reply[$cnt][name]: "+ reply[cnt]['name'])
      if (logTrace) log.trace("reply[$cnt][type]: "+ reply[cnt]['type'])
      if (logTrace) log.trace("reply[$cnt][status]: "+ reply[cnt]['status'])
      if ( getChildDevice(reply[cnt]['id']) != null ) {
        if (logDebug) log.debug "Found child"
      }
      if (getChildDevice(reply[cnt]['id']) == null) {
        if (logDebug) log.debug " Need to add child!"
        if ( reply[cnt]['type'] == 'Door Contact' ) addChildDevice('x86cpu', 'Abode Alarm Contact', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
        if ( reply[cnt]['type'] == 'Occupancy' ) addChildDevice('x86cpu', 'Abode Alarm Motion', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
        if ( reply[cnt]['type'] == 'GLASS' ) addChildDevice('x86cpu', 'Abode Alarm Glass', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
        if ( reply[cnt]['type'] == 'Smoke Detector' ) addChildDevice('x86cpu', 'Abode Alarm Smoke', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
        if ( reply[cnt]['type'] == 'LM' ) addChildDevice('x86cpu', 'Abode Alarm MultiSensor', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
//
        if ( reply[cnt]['type'] == 'Motion Sensor' ) addChildDevice('x86cpu', 'Abode Alarm Motion', reply[cnt]['id'], [name: 'Abode: '+reply[cnt]['name'], isComponent: true])
        added=0
      }
      if (getChildDevice(reply[cnt]['id'])!= null && added == 1) {
        childDevice = getChildDevice(reply[cnt]['id'])
        if ( childDevice.getName() != 'Abode: '+reply[cnt]['name'] ) childDevice.setName('Abode: '+reply[cnt]['name'])
        if (logDebug) log.debug "setting child state: " + reply[cnt]['status']
        if ( reply[cnt]['type'] == 'Door Contact' && reply[cnt]['status'] == 'Closed' ) childDevice.sendEvent(name: "contact", value: "closed", descriptionText: "${childDevice.displayName} is closed")
        if ( reply[cnt]['type'] == 'Door Contact' && reply[cnt]['status'] == 'Opened' ) childDevice.sendEvent(name: "contact", value: "open",   descriptionText: "${childDevice.displayName} is open")
        if ( reply[cnt]['type'] == 'Occupancy' && reply[cnt]['statuses']['motion'] == '0' ) childDevice.sendEvent(name: "motion", value: "inactive", descriptionText: "${childDevice.displayName} is clear")
        if ( reply[cnt]['type'] == 'Occupancy' && reply[cnt]['statuses']['motion'] == '1' ) childDevice.sendEvent(name: "motion", value: "active",   descriptionText: "${childDevice.displayName} detected motion")
        if ( reply[cnt]['type'] == 'GLASS' ) childDevice.sendEvent(name: "shock", value: "clear",   descriptionText: "${childDevice.displayName} clear")
        if ( reply[cnt]['type'] == 'Smoke Detector' ) childDevice.sendEvent(name: "smoke", value: "clear",   descriptionText: "${childDevice.displayName} clear")

        if ( reply[cnt]['type'] == 'LM' ) childDevice.sendEvent(name: "humidity", value: 0, unit: '% RH',  descriptionText: "${childDevice.displayName} humidity is NEW")
        if ( reply[cnt]['type'] == 'LM' ) childDevice.sendEvent(name: "temperature", value: 0, unit: "°${location.temperatureScale}",  descriptionText: "${childDevice.displayName} temperature is NEW")
        if ( reply[cnt]['type'] == 'LM' ) childDevice.sendEvent(name: "illuminance", value: 0, unit: 'lx',  descriptionText: "${childDevice.displayName} lx is NEW")

             childDevice.sendEvent(name: 'temperature', value: temperature.round(2), unit:"°${location.temperatureScale}", descriptionText: "${childDevice.displayName} temperature is "+ temperature + "°${location.temperatureScale}")
               childDevice.sendEvent(name: "illuminance", value: a, unit: 'lx', descriptionText: "${childDevice.displayName} lux is "+ a)

//
        if ( reply[cnt]['type'] == 'Motion Sensor' ) childDevice.sendEvent(name: "motion", value: "inactive", descriptionText: "${childDevice.displayName} is clear")
      }
      cnt++
    }
  }
}

def refresh() {
  if (validateSession()) {
    parsePanel(getPanel())
    if (state.webSocketConnected != true)
      connectEventSocket()
  }
}

def uninstalled() {
  clearLoginState()
  if (logDebug) log.debug 'uninstalled'
  getChildDevices().each {
    deleteChildDevice(it.deviceNetworkId)
  }
}

def disarm() {
  changeMode('standby')
}
def armHome() {
  changeMode('home')
}
def armAway() {
  changeMode('away')
}

def disableDebug(String level) {
  if (logInfo) log.info "Timed elapsed, disabling debug logging"
  device.updateSetting("logDebug", [value: 'false', type: 'bool'])
}
def disableTrace(String level) {
  if (logInfo) log.info "Timed elapsed, disabling trace logging"
  device.updateSetting("logTrace", [value: 'false', type: 'bool'])
}

// isArmed Child Switch
def createIsArmedSwitch() {
  addChildDevice('hubitat', 'Virtual Switch', device.id + '-isArmed', [name: device.name + '-isArmed', isComponent: true])
}

// Abode actions
private baseURL() {
  return 'https://my.goabode.com'
}

private driverUserAgent() {
  return 'AbodeAlarm/0.7.0 Hubitat Elevation driver'
}

private login() {
  if(state.uuid == null) initialize()
  if ( !mfa_seed.isEmpty() && mfa_used ) mfa_code = generateTOTP1(mfa_seed)
  input_values = [
    id: username,
    password: password,
    mfa_code: mfa_code,
    uuid: state.uuid,
    remember_me: 1,
  ]
  reply = doHttpRequest('POST', '/api/auth2/login', input_values)
  if(reply.containsKey('mfa_type')) {
    updateDataValue('mfa_enabled', '1')
    sendEvent(name: 'isLoggedIn', value: "false - requires ${reply.mfa_type}", descriptionText: "Multi-Factor Authentication required: ${reply.mfa_type}")
    device.updateSetting('mfa_used', [value: true, type: 'bool'])
  }
  else if(reply.containsKey('token')) {
    sendEvent(name: 'isLoggedIn', value: true)
    device.updateSetting('showLogin', [value: false, type: 'bool'])
    parseLogin(reply)
    state.access_token = getAccessToken()
    parsePanel(getPanel())
    connectEventSocket()
  }
}

// Make sure we're still authenticated
private validateSession() {
  user = getUser()
  logged_in = user?.id ? true : false
  if(! logged_in) {
    if (state.token) {
      sendEvent(name: 'lastResult', value: 'Not logged in', descriptionText: 'Attempted transaction when not logged in')
      clearLoginState()
    }
    if ( ( !mfa_seed.isEmpty() && mfa_used ) || ( mfa_seed.isEmpty && !mfa_used ) ) { // Attempt login if we have a mfa_seed saved or not using mfa
      login()
      user = getUser()
      logged_in = user?.id ? true : false
      if ( logged_in ) return validateSession() // if we got logged in validateSession again
    }
  }
  else {
    parseUser(user)
    state.access_token = getAccessToken()
  }
  return logged_in
}

def logout() {
  if(state.token && validateSession()) {
    reply = doHttpRequest('POST', '/api/v1/logout')
    terminateEventSocket()
  }
  else {
    sendEvent(name: 'lastResult', value: 'Not logged in', descriptionText: 'Attempted logout when not logged in')
  }
  clearLoginState()
}

private clearLoginState() {
  state.clear()
  unschedule()
  device.updateSetting('showLogin', [value: true, type: 'bool'])
  sendEvent(name: 'isLoggedIn', value: false)
}

// Send a request to change mode to Abode
private changeMode(String new_mode) {
  if(new_mode != device.currentValue('gatewayMode')) {
    // Only update area 1 since area is not returned in event messages
    if (logInfo) log.info "Sending request to change Abode gateway mode to ${new_mode}"
    reply = doHttpRequest('PUT','/api/v1/panel/mode/1/' + new_mode)
    if (reply['area'] == '1') {
      state.localModeChange = new_mode
    }
  } else {
    if (logDebug) log.debug "Gateway is already in mode ${new_mode}"
  }
}

// Process an update from Abode that the mode has changed
private updateMode(String new_mode) {
  if (logInfo) log.info 'Abode gateway mode has changed to ' + new_mode
  sendEvent(name: 'gatewayMode', value: new_mode, descriptionText: 'Gateway mode has changed to ' + new_mode)

  // Set isArmed?
  isArmed = getChildDevice(device.id + '-isArmed')
  if (new_mode == 'standby')
    isArmed.off()
  else {
    isArmed.on()

    // Avoid changing the mode if it's a rebound from a local action
    if (new_mode == state.localModeChange) {
      state.remove('localModeChange')
    } else {
      if (targetModeAway && new_mode == 'away') {
        if (logInfo) log.info 'Changing Hubitat mode to ' + targetModeAway
        location.setMode(targetModeAway)
      }
      else if (targetModeHome) {
        if (logInfo) log.info 'Changing Hubitat mode to ' + targetModeHome
        location.setMode(targetModeHome)
      }
    }
  }
}

// Abode types
private getAccessToken() {
  reply = doHttpRequest('GET','/api/auth2/claims')
  if (logTrace) log.trace reply
  return reply?.access_token
}

private getPanel() {
  doHttpRequest('GET','/api/v1/panel')
}

private getUser() {
  doHttpRequest('GET','/api/v1/user')
}

private parseLogin(Map data) {
  state.token = data.token

  // Login contains a panel hash which is different enough we can't reuse parsePanel()
  ['ip','mac','model','online'].each() { field ->
    updateDataValue(field, data.panel[field])
  }
}

private parseUser(Map user) {
  // Store these for use by Apps
  updateDataValue('abodeID', user.id)
  ['plan','mfa_enabled'].each() { field ->
    updateDataValue(field, user[field])
  }
  // ignore everything else for now
  return user
}

private parsePanel(Map panel) {
  // Update these for use by Apps
  ['ip','online'].each() { field ->
    updateDataValue(field, panel[field])
  }
  areas = parseAreas(panel['areas']) ?: []
  parseMode(panel['mode'], areas) ?: {}

  return panel
}

private parseAreas(Map areas) {
  // Haven't found anything useful other than list of area keys
  areas.keySet()
}

private parseMode(Map mode, Set areas) {
  modeMap = [:]
  // Collect mode for each area
  areas.each() { number ->
    modeMap[number] = mode["area_${number}"]
  }
  // Status is based on area 1 only
  if (device.currentValue('gatewayMode') != modeMap['1'])
    sendEvent(name: 'gatewayMode', value: modeMap['1'], descriptionText: "Gateway mode is ${modeMap['1']}")

  state.modes = modeMap
}

// HTTP methods tuned for Abode
private storeCookies(String cookies) {
  // Cookies are comma separated, colon-delimited pairs
  cookies.split(',').each {
    namevalue = it.split(';')[0].split('=')
    state.cookies[namevalue[0]] = namevalue[1]
  }
}

private doHttpRequest(String method, String path, Map body = [:]) {
  result = [:]
  status = ''
  message = ''
  params = [
    uri: baseURL(),
    path: path,
    headers: ['User-Agent': driverUserAgent()],
  ]
  if (method == 'POST' && body.isEmpty() == false)
    params.body = body
  if (state.token) params.headers['ABODE-API-KEY'] = state.token
  if (state.access_token) params.headers['Authorization'] = "Bearer ${state.access_token}"
  if (state.cookies) params.headers['Cookie'] = state.cookies.collect { key, value -> "${key}=${value}" }.join('; ')

  Closure $parseResponse = { response ->
    if (logTrace) log.trace response.data
    if (logDebug) log.debug "HTTPS ${method} ${path} results: ${response.status}"
    status = response.status.toString()
    result = response.data
    message = result?.message ?: "${method} ${path} successful"
    if (response.headers.'Set-Cookie') storeCookies(response.headers.'Set-Cookie')
  }
  try {
    switch(method) {
      case 'PATCH':
        httpPatch(params, $parseResponse)
        break
      case 'POST':
        httpPostJson(params, $parseResponse)
        break
      case 'PUT':
        httpPut(params, $parseResponse)
        break
      default:
        httpGet(params, $parseResponse)
        break
    }
  } catch(error) {
    // Is this an HTTP error or a different exception?
    if (error.metaClass.respondsTo(error, 'response')) {
      if (logTrace) log.trace error.response.data
      status = error.response.status?.toString()
      result = error.response.data
      message = error.response.data?.message ?:  "${method} ${path} failed"
      log.error "HTTPS ${method} ${path} result: ${error.response.status} ${error.response.data?.message}"
      error.response.data?.errors?.each() { errormsg ->
        log.warn errormsg.toString()
      }
    } else {
      status = 'Exception'
      log.error error.toString()
    }
  }
  if ( !(message =~ /null/) ) sendEvent(name: 'lastResult', value: "${status} ${message}", descriptionText: message, type: 'API call')
  return result
}

// Abode event websocket handling
def connectEventSocket() {
  if (!state.webSocketConnectAttempt) state.webSocketConnectAttempt = 0
  if (logDebug) log.debug "Attempting WebSocket connection for Abode events (attempt ${state.webSocketConnectAttempt})"
  try {
    interfaces.webSocket.connect('wss://my.goabode.com/socket.io/?EIO=3&transport=websocket', headers: [
      'Origin': baseURL() + '/',
      'Cookie': "SESSION=${state.cookies['SESSION']}",
    ])
    if (logDebug) log.debug 'EventSocket connection initiated'
    runEvery5Minutes(checkSocketTimeout)
  }
  catch(error) {
    log.error 'WebSocket connection to Abode event socket failed: ' + error.toString()
  }
}

private terminateEventSocket() {
  if (logDebug) log.debug 'Disconnecting Abode event socket'
  try {
    interfaces.webSocket.close()
    state.webSocketConnected = false
    state.webSocketConnectAttempt = 0
    if (logDebug) log.debug 'EventSocket connection terminated'
  }
  catch(error) {
    log.error 'Disconnect of WebSocket from Abode portal failed: ' + error.toString()
  }
}

// failure handler: validate state and reconnect in 5 seconds
private restartEventSocket() {
  terminateEventSocket()
  runInMillis(5000, refresh)
}

def sendPing() {
  if (logTrace) log.trace 'Sending webSocket ping'
  interfaces.webSocket.sendMessage('2')
}

def sendPong() {
  if (logTrace) log.trace 'Sending webSocket pong'
  interfaces.webSocket.sendMessage('3')
}

def receivePong() {
  runInMillis(state.webSocketPingInterval, sendPing)
}

// This is called every 5 minutes whether we are connected or not
def checkSocketTimeout() {
  if (state.webSocketConnected) {
    responseTimeout = state.lastMsgReceived + state.webSocketPingTimeout + (timeoutSlack*1000)
    if (now() > responseTimeout) {
      log.warn 'Socket ping timeout - Disconnecting Abode event socket'
      restartEventSocket()
    }
  } else {
    connectEventSocket()
  }
}

// Websocket message parsing
private devicesToIgnore() {
  return [
    // Don't need to log what the camera captured
    'Iota Cam'
  ]
}

// These events have corresponding timeline and don't appear actionable
private eventsToIgnore() {
  return [
    // Internal alarm tracking events used by Abode responders
    'alarm.add',
    'alarm.ignore',
    'alarm.del',
    // Nest integration events
    'nest.refresh.true',
  ]
}

String formatEventUser(HashMap jsondata) {
  userdata = ''
  if (jsondata.user_name) {
    userdata += ' by ' + jsondata.user_name
  }
  if (jsondata.mobile_name) {
    userdata += ' using ' + jsondata.mobile_name
  }
  return userdata
}

def syncArmingEvents(String event_type) {
  switch(event_type) {
    case ~/Arming .* Away.*/:
      if (targetModeAway) location.setMode(targetModeAway)
      break
    case ~/Arming .* Home.*/:
      if (targetModeHome) location.setMode(targetModeHome)
      break
    default:
      // ignore it
      break
  }
}

def sendEnabledEvents(
  String alert_value,
  String message,
  String alert_type
) {
  switch(alert_type) {
    // Ignore camera events
    case ~/.* Cam/:
      break

    // User choice to log
    case ~/.* Contact/:     // or event code 5100 open, 5101 closed, 5110 unlocked, 5111 locked
      if (saveContacts)
        sendEvent(name: 'gatewayTimeline', value: alert_value, descriptionText: message, type: alert_type)
      break

    case ~/LM/:
      if (saveContacts)
        sendEvent(name: 'gatewayTimeline', value: alert_value, descriptionText: message, type: alert_type)
      break

    case ~/Occupancy/:
      if (saveContacts)
        sendEvent(name: 'gatewayTimeline', value: alert_value, descriptionText: message, type: alert_type)
      break

    case ~/CUE Automation/:    // or event code 520x
      if (saveAutomation)
        sendEvent(name: 'gatewayTimeline', value: alert_value, descriptionText: message, type: alert_type)
      break

    default:
      sendEvent(name: 'gatewayTimeline', value: alert_value, descriptionText: message, type: alert_type)
      break
  }
}

def parseEvent(String event_text) {
  twovalue = event_text =~ /^\["com\.goabode\.([\w+\.]+)",(.*)\]$/
  a = 0
  b = 0
  temperature = 0
  if (twovalue.find()) {
    event_class = twovalue[0][1]
    event_data = twovalue[0][2]

    if (eventsToIgnore().contains(event_class))
      return

    switch(event_data) {
      // Quoted text
      case ~/^".*"$/:
        message = event_data[1..-2]
        break

      // Unquoted text
      case ~/^\w+$/:
        message = event_data
        break

      // JSON format
      case ~/^\{.*\}$/:
        json_data = parseJson(event_data)
        break

      default:
        log.warn "Abode event ${event_class} has unknown data format: ${event_data}"
        message = event_data
        break
    }
    switch(event_class) {
      case 'gateway.mode':
        updateMode(message)
        break

      // Presence/Geofence updates
      case ~/fence.update.*/:
        if (saveGeofence)
          sendEvent(name: 'gatewayTimeline',
                    value: "${json_data.name}@${json_data.location}=${json_data.state}",
                    descriptionText: json_data.message,
                    type: 'Geofence'
                   )
        break

      case ~/^gateway\.timeline.*/:
        event_type = json_data.event_type
        message = json_data.event_name
        user_info = formatEventUser(json_data)

        if (logDebug) log.debug "${event_class} -${json_data.device_type} ${message}"

        if (event_type == 'Automation') {
          alert_type = 'CUE Automation'
          // Automation puts the rule name in device_name, which is backwards for our purposes
          alert_value = json_data.device_name
        }
        else {
          alert_value = [json_data.device_name, event_type].findAll { it.isEmpty() == false }.join('=')
          if (user_info.isEmpty() == false)
            alert_type = user_info
          else if (json_data.device_type.isEmpty() == false)
            alert_type = json_data.device_type
          else
            alert_type = ''
        }

        // Devices we ignore events for
        if (! devicesToIgnore().contains(json_data.device_name)) {
          if (syncArming) syncArmingEvents(event_type)
            sendEnabledEvents(alert_value, message, alert_type)

          if (saveDevices) {
            if (getChildDevice(json_data.device_id) != null) {
              childDevice=getChildDevice(json_data.device_id)
              if ( json_data.device_type == 'Door Contact' && json_data.event_type == 'Closed' ) childDevice.sendEvent(name: "contact", value: "closed", descriptionText: "${childDevice.displayName} is closed")
              if ( json_data.device_type == 'Door Contact' && json_data.event_type == 'Opened' ) childDevice.sendEvent(name: "contact", value: "open",   descriptionText: "${childDevice.displayName} is open")
            }
          }
        }
        break
      case ~/^device\.update.*/:
        reply = doHttpRequest('GET','/api/v1/devices/'+message)
        if (logTrace) log.trace "reply: ${reply}"

// Occupancy sensor
        if ( getChildDevice(reply[0]['id']) != null && reply[0]['type'] == 'Occupancy' ) {
          childDevice=getChildDevice(reply[0]['id'])
          if (logTrace) log.trace "motion: "+reply[0]['statuses']['motion']
          if ( reply[0]['statuses']['motion'] == '0' ) {
            childDevice.sendEvent(name: "motion", value: "inactive", descriptionText: "${childDevice.displayName} is clear")
            alert_value = reply[0]['name'] + "=inactive"
            message = reply[0]['name'] + " inactive"
          }
          if ( reply[0]['statuses']['motion'] == '1' ) {
            childDevice.sendEvent(name: "motion", value: "active",   descriptionText: "${childDevice.displayName} detected motion")
            alert_value = reply[0]['name'] + "=active"
            message = reply[0]['name'] + " active"
          }
          sendEnabledEvents(alert_value, message, "Occupancy")
        }

// LM (Multi Sensor)
        if ( getChildDevice(reply[0]['id']) != null && reply[0]['type'] == 'LM' ) {
          childDevice=getChildDevice(reply[0]['id'])

// humidity: humidity:20 %
          if ( reply[0]['statuses']['humidity'] != null ) {
             if (logTrace) log.trace "humidity: "+reply[0]['statuses']['humidity']
             (a,b) = reply[0]['statuses']['humidity'].split(' ')
             if (logDebug) log.debug "a = " + a + " AND b = " + b
             if ( a >= 0  && b == '%' ) {
               childDevice.sendEvent(name: "humidity", value: a, unit: '% RH', descriptionText: "${childDevice.displayName} humidity is "+ a + "%")
               alert_value = reply[0]['name'] + "humidity =" + a
               message = reply[0]['name'] + " humidity " + a + "%"
               sendEnabledEvents(alert_value, message, "LM")
             }
          }
// temp: temp:32.1, temperature:90 °F
          if ( reply[0]['statuses']['temp'] != null ) {
             if (logTrace) log.trace "temp: "+reply[0]['statuses']['temp']
             temperature = reply[0]['statuses']['temp']
             if (logDebug) log.debug "location.temperatureScale: " + location.temperatureScale
             if ( location.temperatureScale == "F" ) {
                temperature = (reply[0]['statuses']['temp'] * 1.8) + 32
             }
             childDevice.sendEvent(name: 'temperature', value: temperature.round(2), unit:"°${location.temperatureScale}", descriptionText: "${childDevice.displayName} temperature is "+ temperature + "°${location.temperatureScale}")
             alert_value = reply[0]['name'] + "temperature =" + temperature
             message = reply[0]['name'] + " temperature " + temperature + "°${location.temperatureScale}"
             sendEnabledEvents(alert_value, message, "LM")
          }
// lux:  lux:0 lx
          if ( reply[0]['statuses']['lux'] != null ) {
             if (logTrace) log.trace "lux: "+reply[0]['statuses']['lux']
             (a,b) = reply[0]['statuses']['lux'].split(' ')
             if (logDebug) log.debug "a = " + a + " AND b = " + b
             if ( a >= 0  && b == 'lx' ) {
               childDevice.sendEvent(name: "illuminance", value: a, unit: 'lx', descriptionText: "${childDevice.displayName} lux is "+ a)
               alert_value = reply[0]['name'] + "lux =" + a
               message = reply[0]['name'] + " lux " + a
               sendEnabledEvents(alert_value, message, "LM")
             }
          }

        }
        break
      default:
        if (logDebug) log.debug "Ignoring event ${event_class} ${message}"
        break
    }
  } else {
    log.warn "Unparseable Abode event message: ${event_text}"
  }
}

// Hubitat required method: This method is called with any incoming messages from the web socket server
def parse(String message) {
  state.lastMsgReceived = now()
  if (logTrace) log.trace 'webSocket event raw: ' + message

  // First character is the event type
  packet_type = message.substring(0,1)
  // remainder is the data (optional)
  packet_data = message.substring(1)

  switch(packet_type) {
    case '0':
      if (logDebug) log.debug 'webSocket session open received'
      jsondata = parseJson(packet_data)
      if (jsondata.containsKey('pingInterval')) state.webSocketPingInterval = jsondata['pingInterval']
      if (jsondata.containsKey('pingTimeout'))  state.webSocketPingTimeout  = jsondata['pingTimeout']
      if (jsondata.containsKey('sid'))          state.webSocketSid          = jsondata['sid']
      break

    case '1':
      if (logDebug) log.debug 'webSocket session close received'
      restartEventSocket()
      break

    case '2':
      if (logTrace) log.trace 'webSocket Ping received, sending reply'
      sendPong()
      break

    case '3':
      if (logTrace) log.trace 'webSocket Pong received'
      receivePong()
      break

    case '4':
      // First character of the message indicates purpose
      message_type = packet_data.substring(0,1)
      message_data = packet_data.substring(1)
      switch(message_type) {
        case '0':
          if (logInfo) log.info 'Abode event socket connected'
          runInMillis(state.webSocketPingInterval, sendPing)
          break

        case '1':
          if (logInfo) log.info 'webSocket message = event socket disconnected'
          break

        case '2':
          parseEvent(message_data)
          break

        case '4':
          log.warn 'webSocket message = Error: ' + message_data
          sendEvent(name: 'lastResult', value: 'webSocket error message', descriptionText: message_data, type: 'websocket')

          // Authorization failure message is enclosed in double quotes ;p
          if (message_data == '"Not Authorized"') {
            terminateEventSocket()
            // validate the session and get a new access token
            refresh()
          }
          break

        default:
          log.warn "webSocket message = (unknown:${message_type}): ${message_data}"
          sendEvent(name: 'lastResult', value: 'unknown webSocket message received', descriptionText: message_data, type: 'websocket')
          break
      }
      break

    default:
      log.warn "Unknown webSocket event (${packet_type}) received: " + packet_data
      break
  }
}

// Hubitat required method: This method is called with any status messages from the web socket client connection
def webSocketStatus(String message) {
  if (logTrace) log.trace 'webSocketStatus ' + message
  switch(message) {
    case ~/^status: open.*$/:
      if (logDebug) log.debug 'Connected to Abode event socket'
      sendEvent([name: 'lastResult', value: 'eventSocket connected'])
      state.webSocketConnected = true
      state.webSocketConnectAttempt = 0
		  break

    case ~/^status: closing.*$/:
      if (logDebug) log.debug 'Closing connection to Abode event socket'
      sendEvent([name: 'lastResult', value: 'eventSocket disconnected'])
      state.webSocketConnected = false
      state.webSocketConnectAttempt = 0
      break

    case ~/^failure:(.*)$/:
      log.warn 'Abode event socket connection: ' + message
      state.webSocketConnected = false
      state.webSocketConnectAttempt += 1
      break

    default:
      log.warn 'Abode event socket sent unexpected message: ' + message
      state.webSocketConnected = false
      state.webSocketConnectAttempt += 1
  }

  if ((device.currentValue('isLoggedIn') == true) && !state.webSocketConnected && state.webSocketConnectAttempt < 10)
    runIn(120, 'connectEventSocket')
}

// TOTP groocy code:  https://github.com/osoco/groovy-OTP/blob/master/src/main/groovy/es/osoco/oath/totp/TOTP.groovy

/**
* This method uses the JCE to provide the crypto algorithm.
* HMAC computes a Hashed Message Authentication Code with the
* crypto hash algorithm as a parameter.
*
* @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
* @param keyBytes: the bytes to use for the HMAC key
* @param text: the message or text to be authenticated
*/
private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
  try {
     Mac hmac
     hmac = Mac.getInstance(crypto)
     SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW")
     hmac.init(macKey)
     return hmac.doFinal(text)
   } catch (GeneralSecurityException gse) {
     throw new UndeclaredThrowableException(gse);
   }
}

/**
* This method converts a HEX string to Byte[]
*
* @param hex: the HEX string
* @return: a byte array
*/
private static byte[] hexStr2Bytes(String hex){
  // Adding one byte to get the right conversion
  // Values starting with "0" can be converted
  byte[] bArray = new BigInteger("10" + hex,16).toByteArray()

  // Copy all the REAL bytes, not the "first"
  byte[] ret = new byte[bArray.length - 1]
  for (int i = 0; i < ret.length; i++)
    ret[i] = bArray[i+1]
  return ret
}

/**
 * This method generates a TOTP value for the given
 * set of parameters.
 *
 * @param key: the shared secret, HEX encoded
 * @param time: a value that reflects a time
 * @param returnDigits: number of digits to return
 * @return: a numeric String in base 10 that includes
 *              {@link truncationDigits} digits
*/
String generateTOTP1(String key) {
  Date date = new Date()
  long epoch = date.time / 1000
  Long T = epoch / 30
  String steps = Long.toHexString(T).toUpperCase()
  while (steps.length() < 16) {
    steps = "0" + steps;
  }
  return generateTOTP(base32_decode(key), steps, "6", "HmacSHA1")
}

/**
* This method generates a TOTP value for the given
* set of parameters.
*
* @param key: the shared secret, HEX encoded
* @param time: a value that reflects a time
* @param returnDigits: number of digits to return
* @param crypto: the crypto function to use
*
* @return: a numeric String in base 10 that includes
*              {@link truncationDigits} digits
*/
String generateTOTP(String key,
                    String time,
                    String returnDigits,
                    String crypto){
  int codeDigits = Integer.decode(returnDigits).intValue()
  String result = null;
  int[] DIGITS_POWER =  [ 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 ]

  // Get the HEX in a Byte[]
  byte[] msg = hexStr2Bytes(time)
  byte[] k = hexStr2Bytes(key)

  byte[] hash = hmac_sha(crypto, k, msg)

  // put selected bytes into result int
  int offset = hash[hash.length - 1] & 0xf

  int binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
     (hash[offset + 3] & 0xff)

  int otp = binary % DIGITS_POWER[codeDigits]

  result = Integer.toString(otp)
  while (result.length() < codeDigits) {
    result = "0" + result
  }
  return result
}

//  SOURCE:  view-source:https://tomeko.net/online_tools/base32.php?lang=en
// Return base32 as hex String
String base32_decode(String input) {
  String keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="

  int buffer = 0
  int bitsLeft = 0
  byte[] output = new byte[1]

  int i = 0
  int count = 0

  while (i < input.length() ) {
    String ca = input.charAt(i++)
    int val = keyStr.indexOf(ca)
    if (val >= 0 && val < 32) {
      buffer <<= 5
      buffer |= val
      bitsLeft += 5
      if (bitsLeft >= 8) {
        if ( count == 0 ) {
          output[count++] = (buffer >> (bitsLeft - 8)) & 0xFF
        } else {
          byte[] result = new byte[count+1];
          for(int x = 0; x < count; x++) {
            result[x] = output[x]
          }
          // attempt memory clean up (not sure if required or not)
          output = null
          binding.variables.remove 'output'
          output = result
          result = null
          binding.variables.remove 'result'
          output[count++] = (buffer >> (bitsLeft - 8)) & 0xFF
        }
        bitsLeft -= 8
      }
    }
  }
  return output.encodeHex().toString()
}
