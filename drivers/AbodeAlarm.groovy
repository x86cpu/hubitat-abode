/*
 * Abode Alarm 2024
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
    // Gateway health, reported by Abode and previously discarded
    capability 'PowerSource'
    attribute 'gatewayBattery', 'ENUM', ['normal', 'low']
    attribute 'rfJamming',      'ENUM', ['clear', 'detected']
    attribute 'gatewayOnline',  'ENUM', ['false', 'true']
    attribute 'gatewaySignal',  'NUMBER'
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
    input name: 'deviceComponent',type: 'bool',   title: 'Mark child devices as Components', defaultValue: true,  description: '<em>...Prevents changing or deletion</em>'

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
  device.updateSetting('deviceComponent', [value: true, type: 'bool'])
  device.updateSetting('mfa_code', [value: '', type: 'text'])
  device.updateSetting('mfa_seed', [value: '', type: 'text'])
  initialize()
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
  if ( mfa_code == null ) device.updateSetting('mfa_code', [value: '', type: 'text'])
  if ( mfa_seed == null ) device.updateSetting('mfa_seed', [value: '', type: 'text'])

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
    if ( mfa_seed != null && !mfa_seed.isEmpty() ) state.HEX = base32_decode(mfa_seed)
    if ( mfa_seed != null && !mfa_seed.isEmpty() ) state.MFA = generateTOTP1(mfa_seed)
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
    def drivers = [
      'contact'    : 'Abode Alarm Contact',
      'motion'     : 'Abode Alarm Motion',
      'glass'      : 'Abode Alarm Glass',
      'smoke'      : 'Abode Alarm Smoke',
      'multisensor': 'Abode Alarm MultiSensor',
      'doorbell'   : 'Abode Alarm Doorbell',
      'water'      : 'Abode Alarm Water',
    ]
    def cnt = 0
    while (reply != null && reply[cnt] != null ) {
      def dev  = reply[cnt]
      def kind = deviceKind(dev)
      if (logTrace) log.trace "reply[$cnt]: ${dev}"
      if (logDebug) log.debug "Abode device ${dev['id']} '${dev['name']}' type='${dev['type']}' kind='${kind}' status='${dev['status']}'"

      def childDevice = getChildDevice(dev['id'])
      if (childDevice == null) {
        if (drivers.containsKey(kind)) {
          if (logDebug) log.debug "Adding child device for '${dev['name']}'"
          addChildDevice('x86cpu', drivers[kind], dev['id'], [name: 'Abode: '+dev['name'], isComponent: deviceComponent])
          childDevice = getChildDevice(dev['id'])
        } else if (logDebug) {
          // Keypads and remote controllers report an empty statuses map and
          // nothing but Online/Offline, so a child device would have nothing
          // to display.  Not an error, and not worth a warning on every save.
          log.debug "No child device for Abode type '${dev['type']}' ('${dev['name']}') -- it reports no state"
        }
      }

      if (childDevice != null) {
        if ( childDevice.getName() != 'Abode: '+dev['name'] ) childDevice.setName('Abode: '+dev['name'])
        storeChildData(childDevice, dev)
        updateChildFromDevice(dev)
      }
      cnt++
    }
  }
}

// Reference details from the Abode device record, kept on the child device for
// support and for Apps.  Stored as data values rather than attributes because
// none of it changes during normal operation.
private storeChildData(childDevice, Map dev) {
  def fields = [
    'zone'       : 'zone',
    'uuid'       : 'abodeUUID',
    'group_name' : 'groupName',
    'is_window'  : 'isWindow',
    'model'      : 'model',
    'sub_type'   : 'subType',
    'sensitivity': 'sensitivity',
    'origin'     : 'origin',
    'version'    : 'firmwareVersion',
    'type_tag'   : 'typeTag',
  ]
  fields.each { field, name ->
    def value = dev[field]
    if (value != null && !value.toString().isEmpty() && value.toString() != 'null')
      childDevice.updateDataValue(name, value.toString())
  }
}

def refresh() {
  if (validateSession()) {
    // login() already fetches the panel and opens the event socket, so doing
    // it again here fetched /api/v1/panel twice and opened a second socket
    // that immediately closed the first.  sessionWasRenewed is set by
    // validateSession() in this same execution and so is visible here;
    // webSocketConnected is not, because the status callback that sets it
    // runs in a separate execution and state is loaded once per execution.
    if (state.sessionWasRenewed == true) {
      state.remove('sessionWasRenewed')
    }
    else {
      parsePanel(getPanel())
      if (state.webSocketConnected != true)
        connectEventSocket()
    }
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
  device.updateSetting("logDebug", [value: false, type: 'bool'])
}
def disableTrace(String level) {
  if (logInfo) log.info "Timed elapsed, disabling trace logging"
  device.updateSetting("logTrace", [value: false, type: 'bool'])
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
  if ( mfa_seed != null && !mfa_seed.isEmpty() && mfa_used ) mfa_code = generateTOTP1(mfa_seed)

  // Discard any previous session before authenticating.  doHttpRequest adds
  // ABODE-API-KEY, Authorization and Cookie headers whenever the matching
  // state entries exist, so a stale token from an expired session would
  // otherwise be presented on the login request itself, which Abode answers
  // with 403 Invalid API Key.
  state.remove('token')
  state.remove('access_token')
  state.cookies = [:]

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
  // Cleared on entry so the flag always describes this call.  refresh() reads
  // it immediately after calling us, and any other caller that renewed a
  // session must not leave a stale true behind for the next refresh().
  state.remove('sessionWasRenewed')
  user = getUser()
  logged_in = user?.id ? true : false
  if(! logged_in) {
    if (state.token) {
      sendEvent(name: 'lastResult', value: 'Not logged in', descriptionText: 'Attempted transaction when not logged in')
      clearLoginState()
    }
    // Attempt login whenever unattended authentication is possible: the
    // account does not use MFA, a seed is stored that a code can be derived
    // from, or the user has just supplied a one-time code.  Testing only for
    // (seed && mfa_used) || !mfa_used meant an MFA account with no stored seed
    // matched neither branch and never attempted login at all, leaving the
    // driver permanently logged out with nothing logged to explain why.
    def can_login = !mfa_used ||
                    ( mfa_seed != null && !mfa_seed.isEmpty() ) ||
                    ( mfa_code != null && !mfa_code.isEmpty() )
    if ( can_login ) {
      login()
      user = getUser()
      logged_in = user?.id ? true : false
      if ( logged_in ) {
        // login() has already stored a fresh access token and parsed the
        // panel, so only the user record still needs recording.  This
        // replaced a recursive validateSession() call that re-fetched the
        // /api/v1/user and /api/auth2/claims it had just retrieved.
        parseUser(user)
        state.sessionWasRenewed = true
        return true
      }
    } else {
      log.warn 'Cannot log in unattended: account uses MFA but no MFA seed is stored. Enter a current MFA code in preferences, or save the MFA seed to allow automatic login.'
      sendEvent(name: 'lastResult', value: 'MFA code required', descriptionText: 'Account uses MFA but no seed is stored; automatic login is not possible')
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

  // Set isArmed?  The switch is created at install, but a user can delete it.
  def isArmed = getChildDevice(device.id + '-isArmed')
  if (isArmed == null)
    log.warn "isArmed child switch is missing; run Save Preferences on the Abode device to recreate it"
  else if (new_mode == 'standby')
    isArmed.off()
  else
    isArmed.on()

  if (new_mode != 'standby') {

    // Avoid changing the mode if it's a rebound from a local action
    if (new_mode == state.localModeChange) {
      state.remove('localModeChange')
    } else {
      // Each Abode mode maps to its own Hubitat mode.  Testing targetModeAway
      // first meant that an 'away' event with no Away mode configured fell
      // through and set the Home mode instead.
      if (new_mode == 'away') {
        if (targetModeAway) {
          if (logInfo) log.info 'Changing Hubitat mode to ' + targetModeAway
          location.setMode(targetModeAway)
        }
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
  storeGatewayDetails(data.panel)
  storePermissions(data.permissions)
  updateGatewayHealth(data.panel)

  // How long this session is good for.  Without it there is no way to tell a
  // genuine authentication failure from a simply expired token.
  if (data.expired_at != null) updateDataValue('tokenExpires', data.expired_at.toString())
}

// Gateway and account reference details.  Stored as data values because none
// of it changes in normal operation, but it is the first thing needed when
// diagnosing an installation that is not in front of you.
private storeGatewayDetails(Map panel) {
  if (panel == null) return
  [
    'version'       : 'gatewayVersion',
    'gateway_model' : 'gatewayModel',
    'net_version'   : 'netVersion',
    'rf_version'    : 'rfVersion',
    'zigbee_version': 'zigbeeVersion',
    'z_wave_version': 'zwaveVersion',
    'site_id'       : 'siteID',
    'report_account': 'reportAccount',
    'timezone'      : 'timezone',
    'is_demo'       : 'isDemo',
  ].each { field, name ->
    def value = panel[field]
    if (value != null && !value.toString().isEmpty()) updateDataValue(name, value.toString())
  }

  // xml_version is Abode's API schema version.  A change to it is the warning
  // that field names may have moved, which is exactly how the timeline rename
  // from event_type to event_name_v2 broke this driver silently.
  if (panel['xml_version'] != null) {
    def schema = panel['xml_version'].toString()
    def known  = getDataValue('xmlVersion')
    if (known != null && known != schema)
      log.warn "Abode API schema version changed from ${known} to ${schema} -- field names may have changed"
    updateDataValue('xmlVersion', schema)
  }

  // This driver talks to a hardcoded host.  Abode white-labels the platform to
  // dealers, and an account served from another domain would be refused on
  // every request.  Unconfirmed -- no such account has been seen -- but it
  // costs nothing to detect and would otherwise be invisible.
  def dealer = panel['dealer_domain']?.toString()
  if (dealer != null && !dealer.isEmpty()) {
    updateDataValue('dealerDomain', dealer)
    if (!dealer.startsWith(baseURL()))
      log.warn "Abode reports dealer domain ${dealer} but this driver uses ${baseURL()} -- requests may be rejected"
  }
}

// Account permissions, kept as one value rather than two dozen.  has_timeline
// is checked explicitly: without it Abode sends no timeline events at all, and
// the contact, smoke, water and doorbell children can never update.
private storePermissions(Map permissions) {
  if (permissions == null || permissions.isEmpty()) return
  updateDataValue('permissions', groovy.json.JsonOutput.toJson(permissions))
  def timeline = permissions['has_timeline']
  if (timeline == null || timeline.toString() == '0')
    log.warn 'This Abode account does not include timeline events. Contact, smoke, water and doorbell devices cannot report state without them.'
}

// Live panel health.  These were discarded entirely, so a gateway running on
// battery, with mains power lost, or reporting RF jamming -- which on an alarm
// panel is an attack indicator -- was invisible to Hubitat.  They refresh on
// poll only; no websocket event carrying them has been observed.
private updateGatewayHealth(Map panel) {
  if (panel == null) return

  if (panel['ac_fail'] != null) {
    def source = panel['ac_fail'].toString() == '0' ? 'mains' : 'battery'
    if (device.currentValue('powerSource') != source) {
      sendEvent(name: 'powerSource', value: source, descriptionText: "Abode gateway power source is ${source}")
      if (source != 'mains') log.warn 'Abode gateway has lost mains power'
    }
  }

  if (panel['battery'] != null) {
    def battery = panel['battery'].toString() == '0' ? 'normal' : 'low'
    if (device.currentValue('gatewayBattery') != battery) {
      sendEvent(name: 'gatewayBattery', value: battery, descriptionText: "Abode gateway battery is ${battery}")
      if (battery != 'normal') log.warn 'Abode gateway reports a low battery'
    }
  }

  if (panel['jam'] != null) {
    def jam = panel['jam'].toString() == '0' ? 'clear' : 'detected'
    if (device.currentValue('rfJamming') != jam) {
      sendEvent(name: 'rfJamming', value: jam, descriptionText: "Abode gateway RF jamming is ${jam}")
      if (jam != 'clear') log.warn 'Abode gateway reports RF jamming'
    }
  }

  if (panel['online'] != null) {
    def online = panel['online'].toString() == '1' ? 'true' : 'false'
    if (device.currentValue('gatewayOnline') != online)
      sendEvent(name: 'gatewayOnline', value: online, descriptionText: "Abode gateway online is ${online}")
  }

  // rssi is the gateway's own radio link, which is a cellular signal only on
  // a gateway running the cellular backup radio.  It was named cellularSignal
  // on the assumption that it always was; an ethernet-only F1 reporting
  // is_cellular 0 proved otherwise.  parsePanel stores isCellular alongside.
  if (panel['rssi'] != null && panel['rssi'].toString().isInteger())
    sendEvent(name: 'gatewaySignal', value: panel['rssi'].toString().toInteger())
}

private parseUser(Map user) {
  // Store these for use by Apps
  updateDataValue('abodeID', user.id)
  ['plan','mfa_enabled'].each() { field ->
    updateDataValue(field, user[field])
  }

  // Reference details only.  Name, address, coordinates, phone number, email
  // and cms_code are deliberately not stored: data values are plain text on
  // the device page and end up in pasted logs, and cms_code is the central
  // monitoring dispatch passcode.
  [
    'user_id'   : 'userID',
    'temp_scale': 'tempScale',
    'timezone'  : 'timezone',
    'plan_id'   : 'planID',
    'owner'     : 'owner',
    // Account state.  cms_active is whether professional monitoring will
    // actually dispatch; plan_active is whether the plan is current, and a
    // lapsed plan silently stops timeline events, which is the failure mode
    // hardest to diagnose from the Hubitat side.
    'cms_active'      : 'cmsActive',
    'cms_adhoc_active': 'cmsAdhocActive',
    'plan_active'     : 'planActive',
  ].each { field, name ->
    def value = user[field]
    if (value != null && !value.toString().isEmpty()) updateDataValue(name, value.toString())
  }

  // A non-owner account may not be permitted to arm, disarm or read the
  // timeline, which surfaces as 403s on specific calls while login succeeds.
  if (user['owner'] != null && user['owner'].toString() == '0')
    log.warn 'This Abode account is not the system owner; some operations may be refused'

  return user
}

private parsePanel(Map panel) {
  // Update these for use by Apps
  ['ip','online'].each() { field ->
    updateDataValue(field, panel[field])
  }

  // Context for the gatewaySignal reading.  has_wifi is deliberately not
  // stored: this endpoint reports 1 on a gateway with no wifi radio at all,
  // while the login payload reports 0 for that same gateway.
  if (panel['is_cellular'] != null)
    updateDataValue('isCellular', panel['is_cellular'].toString())

  storeGatewayDetails(panel)
  updateGatewayHealth(panel)
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
  // Multiple Set-Cookie headers arrive joined by commas, and each one is a
  // semicolon-delimited list whose first element is the name=value pair.
  // Attribute values such as Expires contain their own commas, so splitting on
  // comma also produces fragments that are not name=value pairs.  Indexing
  // those blindly threw ArrayIndexOutOfBoundsException, which aborted the loop
  // and discarded every cookie after the break -- including SESSION, which
  // Abode requires on later requests.
  def attributes = ['path', 'domain', 'expires', 'max-age', 'samesite', 'secure', 'httponly', 'version']
  cookies.split(',').each {
    def namevalue = it.split(';')[0].split('=', 2)
    if (namevalue.size() == 2) {
      def name = namevalue[0].trim()
      if (name && !attributes.contains(name.toLowerCase()))
        state.cookies[name] = namevalue[1]
    }
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
      // A 401 or 403 here is how Abode reports "no valid session".  It is the
      // normal result of any call made after a logout or once a token has
      // expired, and validateSession() recovers by logging back in.  Logging
      // it as an error made routine re-authentication look like a failure.
      // This exception carries no response object, so the status code has to
      // be read back out of its message.
      def text = error.toString()
      def auth = (text =~ /status code: (401|403)/)
      if (auth.find()) {
        message = "${method} ${path} - not logged in"
        if (logDebug) log.debug "HTTPS ${method} ${path}: ${auth.group(1)} - not logged in, will re-authenticate"
      } else {
        log.error text
      }
    }
  }
  if ( !(message =~ /null/) ) sendEvent(name: 'lastResult', value: "${status} ${message}", descriptionText: message, type: 'API call')
  if (logTrace) log.trace "EXIT doHttpRequest()"
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

// Abode prefixes the timeline event_type with the device name, so a contact
// opening arrives as "Garage Inside Door Opened" rather than "Opened".  The
// event_name_v2 field carries the bare action and is what should be matched.
// Fall back to stripping the device name from event_type for gateways that do
// not send the newer field.
private timelineAction(Map json_data) {
  def action = json_data.event_name_v2?.toString() ?: ''
  if (action.isEmpty()) {
    action = json_data.event_type?.toString() ?: ''
    def name = json_data.device_name?.toString() ?: ''
    if (!name.isEmpty() && action.startsWith(name)) action = action.substring(name.length())
  }
  return action.trim()
}

// Canonical device kind for dispatch.  type_tag is a machine identifier that
// survives the display-string renames Abode periodically makes, so prefer it
// and fall back to the type / device_type display string.  The water sensor
// and doorbell tags are unconfirmed -- no such device was available to observe
// -- but an unrecognised tag falls through to the display string, which is the
// behaviour this driver has always relied on.
private deviceKind(Map dev) {
  def by_tag = [
    'device_type.door_contact'     : 'contact',
    'device_type.povs'             : 'motion',
    'device_type.lm'               : 'multisensor',
    'device_type.glass'            : 'glass',
    'device_type.smoke_detector'   : 'smoke',
    'device_type.water_sensor'     : 'water',
    'device_type.doorbell'         : 'doorbell',
    'device_type.keypad'           : 'keypad',
    'device_type.remote_controller': 'remote',
  ]
  def by_type = [
    'door contact'     : 'contact',
    'occupancy'        : 'motion',
    'motion sensor'    : 'motion',
    'lm'               : 'multisensor',
    'glass'            : 'glass',
    'smoke detector'   : 'smoke',
    'water sensor'     : 'water',
    'doorbell'         : 'doorbell',
    'keypad'           : 'keypad',
    'remote controller': 'remote',
  ]
  def tag = dev?.type_tag?.toString()?.toLowerCase()
  if (tag != null && by_tag.containsKey(tag)) return by_tag[tag]
  def type = (dev?.type ?: dev?.device_type)?.toString()?.toLowerCase()
  if (type != null && by_type.containsKey(type)) return by_type[type]
  return ''
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
    case ~/.* Contact/:
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

    case ~/Doorbell/:
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
  def twovalue = event_text =~ /^\["com\.goabode\.([\w+\.]+)",(.*)\]$/
  def json_data = [:]
  def message = ''
  def event_type = ''
  def alert_value = ''
  def alert_type = ''
  if (twovalue.find()) {
    def event_class = twovalue[0][1]
    def event_data = twovalue[0][2]

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
        def is_alarm = json_data.is_alarm
        def event_code = json_data.event_code
        message = json_data.event_name
        def user_info = formatEventUser(json_data)

        if (logDebug) log.debug "${event_class} -${json_data.device_type} ${message}"

        if (event_type == 'Automation') {
          alert_type = 'CUE Automation'
          // Automation puts the rule name in device_name, which is backwards for our purposes
          alert_value = json_data.device_name
        } else {
          alert_value = [json_data.device_name, timelineAction(json_data)].findAll { it != null && it.isEmpty() == false }.join('=')
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
            childDevice = getChildDevice(json_data.device_id)
            if (childDevice != null) {
              def kind    = deviceKind(json_data)
              def action  = timelineAction(json_data).toLowerCase()
              def handled = true
              switch (kind) {
                case 'contact':
                  if (action in ['closed', 'close'])
                    childDevice.sendEvent(name: "contact", value: "closed", descriptionText: "${childDevice.displayName} is closed")
                  else if (action in ['opened', 'open'])
                    childDevice.sendEvent(name: "contact", value: "open", descriptionText: "${childDevice.displayName} is open")
                  else
                    handled = false
                  break

                case 'smoke':
                  if (action.contains('clear')) {
                    childDevice.sendEvent(name: "smoke", value: "clear", descriptionText: "${childDevice.displayName} is clear")
                  } else if (action.contains('alarm') || action.contains('smoke')) {
                    childDevice.sendEvent(name: "smoke", value: "detected", descriptionText: "${childDevice.displayName} is detected")
                    runIn(smokeClearDelay(), "smokeClear", [data: ["cid": json_data.device_id], overwrite: false])
                  } else {
                    handled = false
                  }
                  break

                case 'water':
                  if (action.contains('clear') || action.contains('dry'))
                    childDevice.sendEvent(name: "water", value: "dry", descriptionText: "${childDevice.displayName} is dry")
                  else if (action.contains('detect') || action.contains('wet'))
                    childDevice.sendEvent(name: "water", value: "wet", descriptionText: "${childDevice.displayName} is wet")
                  else
                    handled = false
                  break

                case 'doorbell':
                  if (action.contains('press') || action.contains('push')) {
                    childDevice.sendEvent(name: "button", value: "pushed", descriptionText: "${childDevice.displayName} is pushed")
                    childDevice.sendEvent(name: "pushed", value: 1, isStateChange: true, descriptionText: "${childDevice.displayName} button 1 was pushed")
                    runIn(60, "doorbellOff", [data: ["cid": json_data.device_id], overwrite: false])
                  } else {
                    handled = false
                  }
                  break

                case 'glass':
                  // No clear event has ever been observed from Abode for GLASS,
                  // so the scheduled reset is the only thing that restores it.
                  if (logDebug) log.debug "Got GLASS event: " + json_data
                  childDevice.sendEvent(name: "shock", value: "detected", descriptionText: "${childDevice.displayName} is detected")
                  runIn(60, "glassClear", [data: ["cid": json_data.device_id], overwrite: false])
                  break

                default:
                  handled = false
                  break
              }
              if (!handled)
                log.warn "No handler matched Abode event: kind='${kind}' action='${action}' device='${json_data.device_name}' -- please report this with trace logging enabled"
            } else {
              if (logDebug) log.debug "Got event for a device with no child: " + json_data
            }
          }
        }
// Panic Alarm
        if ( is_alarm == 1 ) log.debug "Alarm event detected"
        break
      case ~/^device\.update.*/:
        reply = doHttpRequest('GET','/api/v1/devices/'+message)
        if (logTrace) log.trace "reply: ${reply}"
        if ( reply != null && reply[0] != null ) updateChildFromDevice(reply[0])
        break
      default:
        if (logDebug) log.debug "Ignoring event ${event_class} ${message}"
        break
    }
  } else {
    log.warn "Unparseable Abode event message: ${event_text}"
  }
}

// Abode reports a fault map on every device and none of it was used, so a
// tampered, jammed or unresponsive sensor looked perfectly healthy in Hubitat.
// low_battery and tempered map onto standard Hubitat attributes; the remaining
// keys are summarised into one deviceFault string so a new fault type Abode
// adds later still surfaces instead of being silently dropped.
private updateChildFaults(childDevice, Map dev) {
  def faults = dev['faults'] ?: [:]

  if (!faults.isEmpty()) {
    def active = faults.findAll { key, value ->
      value != null && value.toString() != '0' && value.toString().toLowerCase() != 'false'
    }.keySet().sort()

    def low = active.contains('low_battery') ? 'true' : 'false'
    if (childDevice.currentValue('lowBattery') != low)
      childDevice.sendEvent(name: 'lowBattery', value: low, descriptionText: "${childDevice.displayName} low battery is ${low}")

    def tamper = active.contains('tempered') ? 'detected' : 'clear'
    if (childDevice.currentValue('tamper') != tamper)
      childDevice.sendEvent(name: 'tamper', value: tamper, descriptionText: "${childDevice.displayName} tamper is ${tamper}")

    def summary = active.isEmpty() ? 'none' : active.join(', ')
    if (childDevice.currentValue('deviceFault') != summary) {
      childDevice.sendEvent(name: 'deviceFault', value: summary, descriptionText: "${childDevice.displayName} faults: ${summary}")
      if (!active.isEmpty())
        log.warn "Abode reports fault(s) on ${childDevice.displayName}: ${summary}"
    }
  }

  // bypass is not part of the fault map but is the same kind of hidden state:
  // a sensor bypassed in the Abode app is excluded from the alarm, and Hubitat
  // previously had no way of knowing that.
  if (dev.containsKey('bypass')) {
    def bypassed = (dev['bypass'] != null && dev['bypass'].toString() != '0') ? 'true' : 'false'
    if (childDevice.currentValue('bypassed') != bypassed) {
      childDevice.sendEvent(name: 'bypassed', value: bypassed, descriptionText: "${childDevice.displayName} bypassed is ${bypassed}")
      if (bypassed == 'true')
        log.warn "${childDevice.displayName} is bypassed in Abode and will not trigger the alarm"
    }
  }
}

// Apply the state carried in an Abode device record to its child device.
// Used both by websocket device.update events and by the initial sync when
// children are created, so the two paths cannot drift apart.
private updateChildFromDevice(Map dev) {
  def childDevice = getChildDevice(dev['id'])
  if (childDevice == null) return

  updateChildFaults(childDevice, dev)

  def kind     = deviceKind(dev)
  def statuses = dev['statuses'] ?: [:]

  switch (kind) {
    case 'contact':
      // Contacts carry their real state in statuses.open.  There was no
      // contact handler here at all, so a child only ever changed state from
      // a timeline event -- and those stopped matching when Abode renamed the
      // event strings.  The 'status' display string is the fallback.
      def open = statuses['open']?.toString()
      if (open == null) {
        def shown = dev['status']?.toString()?.toLowerCase()
        if (shown in ['open', 'opened'])        open = '1'
        else if (shown in ['closed', 'close'])  open = '0'
      }
      if (open == '1')
        childDevice.sendEvent(name: "contact", value: "open", descriptionText: "${childDevice.displayName} is open")
      else if (open == '0')
        childDevice.sendEvent(name: "contact", value: "closed", descriptionText: "${childDevice.displayName} is closed")
      break

    case 'motion':
      def motion = statuses['motion']?.toString()
      if (logTrace) log.trace "motion: ${motion} sub_type: ${dev['sub_type']}"
      if (motion == '1') {
        childDevice.sendEvent(name: "motion", value: "active", descriptionText: "${childDevice.displayName} detected motion")
        sendEnabledEvents(dev['name'] + "=active", dev['name'] + " active", "Occupancy")
        // sub_type 0 sensors have not been observed sending the clearing
        // update, so schedule one.  Abode supplies the sensor's own
        // occupancy_timer for this; 60 seconds used to be hardcoded.
        if ( dev['sub_type']?.toString() == '0' ) {
          def timer = 60
          if ( dev['occupancy_timer'] != null && dev['occupancy_timer'].toString().isInteger() )
            timer = dev['occupancy_timer'].toString().toInteger()
          runIn(timer, "motionOff", [data: ["cid": dev['id']], overwrite: false])
        }
      } else if (motion == '0') {
        childDevice.sendEvent(name: "motion", value: "inactive", descriptionText: "${childDevice.displayName} is clear")
        sendEnabledEvents(dev['name'] + "=inactive", dev['name'] + " inactive", "Occupancy")
      }
      break

    case 'multisensor':
      updateMultiSensor(childDevice, dev, statuses)
      break

    case 'glass':
    case 'smoke':
    case 'water':
    case 'doorbell':
      // These report an empty statuses map, so there is no state to apply.
      // Their children are driven entirely by timeline events and the
      // scheduled resets.  Seed a benign starting value when the child has
      // none yet, but never overwrite a value that is already set -- doing so
      // unconditionally is what used to wipe real readings on every save.
      if (logTrace) log.trace "${kind} device record: ${dev}"
      if (kind == 'glass' && childDevice.currentValue('shock') == null)
        childDevice.sendEvent(name: "shock", value: "clear", descriptionText: "${childDevice.displayName} clear")
      if (kind == 'smoke' && childDevice.currentValue('smoke') == null)
        childDevice.sendEvent(name: "smoke", value: "clear", descriptionText: "${childDevice.displayName} clear")
      if (kind == 'water' && childDevice.currentValue('water') == null)
        childDevice.sendEvent(name: "water", value: "dry", descriptionText: "${childDevice.displayName} is dry")
      if (kind == 'doorbell' && childDevice.currentValue('button') == null)
        childDevice.sendEvent(name: "button", value: "released", descriptionText: "${childDevice.displayName} is released")
      break

    default:
      break
  }
}

// LM multi sensor: humidity and lux arrive with their unit appended ("31 %",
// "0 lx") while temp is a bare Celsius number.  Abode also sends a pre-rounded
// 'temperature' field, which is deliberately ignored in favour of converting
// the more precise Celsius value.
private updateMultiSensor(childDevice, Map dev, Map statuses) {
  if ( statuses['humidity'] != null ) {
    if (logTrace) log.trace "humidity: " + statuses['humidity']
    def parts = statuses['humidity'].toString().split(' ')
    if (parts.size() >= 2 && parts[0].isInteger() && parts[0].toInteger() >= 0 && parts[1] == '%') {
      def humidity = parts[0].toInteger()
      childDevice.sendEvent(name: "humidity", value: humidity, unit: '% RH', descriptionText: "${childDevice.displayName} humidity is ${humidity}%")
      sendEnabledEvents(dev['name'] + " humidity=" + humidity, dev['name'] + " humidity " + humidity + "%", "LM")
    }
  }

  if ( statuses['temp'] != null ) {
    if (logTrace) log.trace "temp: " + statuses['temp']
    float temperature = statuses['temp'].toString().toFloat()
    if ( location.temperatureScale == "F" ) temperature = (temperature * 1.8) + 32
    def reading = temperature.round(1)
    childDevice.sendEvent(name: "temperature", value: reading, unit: "°${location.temperatureScale}", descriptionText: "${childDevice.displayName} temperature is ${reading}°${location.temperatureScale}")
    sendEnabledEvents(dev['name'] + " temperature=" + reading, dev['name'] + " temperature " + reading + "°${location.temperatureScale}", "LM")
  }

  if ( statuses['lux'] != null ) {
    if (logTrace) log.trace "lux: " + statuses['lux']
    def parts = statuses['lux'].toString().split(' ')
    if (parts.size() >= 2 && parts[0].isInteger() && parts[0].toInteger() >= 0 && parts[1] == 'lx') {
      def lux = parts[0].toInteger()
      childDevice.sendEvent(name: "illuminance", value: lux, unit: 'lx', descriptionText: "${childDevice.displayName} lux is ${lux}")
      sendEnabledEvents(dev['name'] + " lux=" + lux, dev['name'] + " lux " + lux, "LM")
    }
  }
}

// Safety net delay before a smoke alarm is assumed clear.  Abode does send a
// clear event, but it has never been observed here, so this only applies when
// one never arrives.  Longer than the doorbell and glass resets because
// clearing a real smoke alarm early is worse than showing it a while longer.
private smokeClearDelay() {
  return 300
}

private motionOff(data) {
   if (logDebug) log.debug "motionOff parameter: $data"
   if (logDebug) log.debug "cid : " + data.cid
   if ( getChildDevice(data.cid) != null ) {
     childDevice=getChildDevice(data.cid)
     childDevice.sendEvent(name: "motion", value: "inactive", descriptionText: "${childDevice.displayName} is clear")
     alert_value = childDevice.displayName + "=inactive"
     message = childDevice.displayName + " inactive"
     sendEnabledEvents(alert_value, message, "Occupancy")
   }
}

private doorbellOff(data) {
   if (logDebug) log.debug "doorbellOff parameter: $data"
   if (logDebug) log.debug "cid : " + data.cid
   if ( getChildDevice(data.cid) != null ) {
     childDevice=getChildDevice(data.cid)
     childDevice.sendEvent(name: "button", value: "released", descriptionText: "${childDevice.displayName} is released")
     alert_value = childDevice.displayName + "=Button released"
     message = childDevice.displayName + " released"
     sendEnabledEvents(alert_value, message, "Doorbell")
   }
}

private smokeClear(data) {
   if (logDebug) log.debug "smokeClear parameter: $data"
   if (logDebug) log.debug "cid : " + data.cid
   if ( getChildDevice(data.cid) != null ) {
     childDevice=getChildDevice(data.cid)
     childDevice.sendEvent(name: "smoke", value: "clear", descriptionText: "${childDevice.displayName} is clear")
     alert_value = childDevice.displayName + "=Smoke Detector clear"
     message = childDevice.displayName + " clear"
     sendEnabledEvents(alert_value, message, "Smoke Detector")
   }
}

private glassClear(data) {
   if (logDebug) log.debug "glassClear parameter: $data"
   if (logDebug) log.debug "cid : " + data.cid
   if ( getChildDevice(data.cid) != null ) {
     childDevice=getChildDevice(data.cid)
     childDevice.sendEvent(name: "shock", value: "clear", descriptionText: "${childDevice.displayName} is clear")
     alert_value = childDevice.displayName + "=GLASS clear"
     message = childDevice.displayName + " clear"
     sendEnabledEvents(alert_value, message, "GLASS")
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

  // isLoggedIn is declared as a String attribute, so currentValue returns
  // "true" rather than the boolean.  Comparing against true was never
  // satisfied, so this reconnect never ran and recovery depended entirely on
  // the five minute socket timeout poll.
  if ((device.currentValue('isLoggedIn')?.toString() == 'true') && !state.webSocketConnected && state.webSocketConnectAttempt < 10)
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
