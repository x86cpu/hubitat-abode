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

    // Alarm and monitoring state.  These exist so a Hubitat rule can act on
    // them: none of it was previously visible anywhere in Hubitat.
    attribute 'lastAlarm',        'String'
    attribute 'armedWithFaults',  'ENUM', ['false', 'true']
    attribute 'monitoringActive', 'ENUM', ['false', 'true']
    attribute 'testModeActive',   'ENUM', ['false', 'true']
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
    input name: 'armConfirm',     type: 'bool',   title: 'Confirm arming when faulted',      defaultValue: true,  description: '<em>Re-send the request Abode requires when Arm Fault Type is Confirm Arm</em>'

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
      if (logTrace) log.trace "reply[$cnt]: ${redact(dev)}"
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

// Hubitat does not apply defaultValue to a device that already exists, so an
// upgraded install reads this setting as null.  Treating null as false would
// disable the feature for exactly the people who never chose to disable it.
private armConfirmEnabled() {
  return (settings.armConfirm == null) ? true : settings.armConfirm
}

// Send a request to change mode to Abode
private changeMode(String new_mode) {
  // gatewayMode is only as fresh as the last websocket notice, and Abode has
  // been seen sitting on a mode change for 39 seconds.  Dropping a request
  // because the stale attribute already reads the target mode is how an arm
  // silently does nothing.  Only skip when there is nothing in flight.
  def pending = state.localModeChange
  if (new_mode == device.currentValue('gatewayMode') && (pending == null || pending == new_mode)) {
    if (logInfo) log.info "Abode gateway is already in mode ${new_mode}; no request sent"
    return
  }

  // Only update area 1 since area is not returned in event messages
  if (logInfo) log.info "Sending request to change Abode gateway mode to ${new_mode}"
  reply = doHttpRequest('PUT','/api/v1/panel/mode/1/' + new_mode, [:], true)
  if (reply['area'] == '1') {
    state.localModeChange = new_mode
    state.remove('modeChangeRetry')
    return
  }

  // The request did not take.  Re-authentication recovers a missing session on
  // its own, so leave those alone; anything else may be a fault refusal.
  if (state.lastHttpStatus == '401' || state.lastHttpStatus == '403') return
  handleModeChangeFailure(new_mode)
}

// Abode refuses an arm while sensors are faulted when the account's Arm Fault
// Type is 'Confirm Arm' -- the app shows a prompt and arms on a second tap.
// There is no confirmation parameter or endpoint: repeating the identical
// request inside Abode's window is the confirmation.  Measured on a live
// system, repeats at 0.4s, 4.9s, 15.0s, 28.7s and 30.5s all armed, while
// repeats at 58.0s and beyond were refused again, so the window closes
// somewhere past 30 seconds.  Two seconds sits well inside it, and the first
// of those measurements had both requests in flight at once, so there is no
// minimum settling time to respect either.
//
// Recovery keys off the request having failed, not off recognising a status
// code.  615 is not an HTTP status at all -- HTTP defines only 1xx through
// 5xx -- so a vendor that invented it can renumber it, and matching on it
// would be no more durable than matching on its reason phrase.
private handleModeChangeFailure(String new_mode) {
  if (!armConfirmEnabled()) {
    log.warn "Abode refused the change to ${new_mode} (status ${state.lastHttpStatus}).  Enable 'Confirm arming when faulted' to re-send the request Abode needs in order to arm with faulted sensors."
    return
  }
  // One retry only.  A second failure is not a confirmation prompt, and
  // repeating would hammer the panel.
  if (state.modeChangeRetry == new_mode) {
    state.remove('modeChangeRetry')
    log.error "Abode refused the change to ${new_mode} twice; giving up.  Last status was ${state.lastHttpStatus}."
    return
  }
  state.modeChangeRetry = new_mode
  log.warn "Abode refused the change to ${new_mode} (status ${state.lastHttpStatus}); re-sending to confirm arming with faulted sensors"
  runInMillis(2000, 'retryModeChange', [data: [mode: new_mode]])
}

def retryModeChange(data) {
  changeMode(data.mode)
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
  if (logTrace) log.trace redact(reply)
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

// caller_handles_errors says the caller inspects the result and reports what
// it did about a refusal.  Abode answering "no, confirm first" is a normal
// step in arming, not a failure, and logging it red immediately above the
// warn describing the recovery made a working exchange look broken.
private doHttpRequest(String method, String path, Map body = [:], Boolean caller_handles_errors = false) {
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
    if (logTrace) log.trace redact(response.data)
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
      if (logTrace) log.trace redact(error.response.data)
      status = error.response.status?.toString()
      result = error.response.data
      message = error.response.data?.message ?:  "${method} ${path} failed"
      log.error "HTTPS ${method} ${path} result: ${error.response.status} ${error.response.data?.message}"
      error.response.data?.errors?.each() { errormsg ->
        log.warn errormsg.toString()
      }
    } else {
      // This exception carries no response object, so the status code has to
      // be read back out of its message.  Capture whatever number is there
      // rather than a fixed list: Abode returns codes outside the HTTP range
      // (615 'Mode change fault'), and callers decide what to do from the
      // fact that the call failed, not from the number itself.
      def text   = error.toString()
      def coded  = (text =~ /status code: (\d+)/)
      status     = coded.find() ? coded.group(1) : 'Exception'
      def phrase = (text =~ /reason phrase: (.+?)\s*$/)
      def reason = phrase.find() ? phrase.group(1) : ''
      message    = "${method} ${path} failed"

      if (status == '401' || status == '403') {
        // A 401 or 403 here is how Abode reports "no valid session".  It is the
        // normal result of any call made after a logout or once a token has
        // expired, and validateSession() recovers by logging back in.  Logging
        // it as an error made routine re-authentication look like a failure.
        message = "${method} ${path} - not logged in"
        if (logInfo) log.info "HTTPS ${method} ${path}: ${status} - not logged in, will re-authenticate"
      }
      else if (status != 'Exception') {
        // Abode answered and refused.  There is a status to act on, and it is
        // recorded in lastResult either way.
        if (reason) message = "${method} ${path} - ${reason}"
        if (caller_handles_errors) {
          if (logDebug) log.debug "HTTPS ${method} ${path}: ${status} ${reason}"
        } else {
          log.error "HTTPS ${method} ${path}: ${status} ${reason}"
        }
      }
      else {
        // No status code at all: the request never completed.  Nothing
        // recovered from this and the raw text is the only clue there is.
        log.error text
      }
    }
  }
  // Recorded so a caller can tell a refusal from a transport failure without
  // having to reparse the exception text.
  state.lastHttpStatus = status
  if ( !(message =~ /null/) ) sendEvent(name: 'lastResult', value: "${status} ${message}", descriptionText: message, type: 'API call')
  if (logTrace) log.trace "EXIT doHttpRequest()"
  return result
}

// Abode event websocket handling
def connectEventSocket() {
  if (!state.webSocketConnectAttempt) state.webSocketConnectAttempt = 0
  // Never stack a socket on top of a live one.  A second connect silently
  // displaces the first, and the close that results is indistinguishable from
  // a real disconnect.  Closing deliberately first keeps it to one socket and
  // makes the replacement visible in the log.
  if (state.webSocketConnected == true) {
    if (logDebug) log.debug 'Replacing the existing Abode event socket'
    terminateEventSocket()
  }
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

// True when a socket came up so recently that a close arriving now is almost
// certainly the one it displaced.  Hubitat gives no socket identity in the
// status callback, so recency is the only thing available to tell them apart.
// The cost of a false positive is bounded: a genuine close ignored here is
// still caught by checkSocketTimeout()'s ping deadline within five minutes.
private socketCloseIsStale() {
  def opened = state.webSocketOpenedAt
  return (opened != null && (now() - opened) < 3000)
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
    // Sent with an empty payload whenever a CUE automation runs.  The
    // timeline event for the same automation carries everything usable, so
    // this one is noise -- and noise that the new unhandled-class warning
    // would otherwise report on every rule that fires.
    'automation',
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

// Abode's wording for this event varies by source and has changed over time.
// Observed forms include 'Arming - Away (Exit Timer Started)', 'Hub Arming w/
// Fault(s) - Home (Exit Timer Started)' and the event_name_v2 wording 'System
// arming with faults (Home mode exit timer started)'.  The previous matcher
// used case ~/Arming .* Away.*/, and a regex in a Groovy case has to match the
// whole string, so none of the current wordings matched and this preference
// quietly did nothing.
def syncArmingEvents(String action) {
  def act = (action ?: '').toLowerCase()
  // \barming\b does not match 'disarming': 's' and 'a' are both word
  // characters, so there is no boundary between them.
  if (!(act =~ /\barming\b/).find()) return
  // The sibling path in updateGatewayMode logs before it calls setMode, and
  // this one did not.  That made a preference which had been silently doing
  // nothing since 2020 impossible to confirm from the driver log alone --
  // proving the fix meant cross-referencing the hub's own location events by
  // millisecond.  Nobody is going to do that twice.
  if (act.contains('away')) {
    if (targetModeAway) {
      if (logInfo) log.info 'Changing Hubitat mode to ' + targetModeAway + ' at exit delay start'
      location.setMode(targetModeAway)
    }
  }
  else if (act.contains('home')) {
    if (targetModeHome) {
      if (logInfo) log.info 'Changing Hubitat mode to ' + targetModeHome + ' at exit delay start'
      location.setMode(targetModeHome)
    }
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
        def kind       = deviceKind(json_data)
        def action     = timelineAction(json_data).toLowerCase()

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
          if (syncArming) syncArmingEvents(action)
          sendEnabledEvents(alert_value, message, alert_type)

          if (saveDevices) {
            childDevice = getChildDevice(json_data.device_id)
            if (childDevice != null) {
              def plan = deviceEventPlan(kind, action, json_data?.event_code?.toString() ?: '')
              if (plan == null) {
                // Not a debug line.  The sensors most worth getting right --
                // smoke, water, the doorbell -- are ones that cannot be tested
                // here, so the only way a missed event string ever gets fixed
                // is if the person it happened to can see it without having
                // first known to turn debug logging on.
                log.warn "Abode sent a device event this driver does not handle: ${describeEvent(json_data, kind, action)} -- please report this line"
              }
              else {
                plan.events.each { ev ->
                  def args = [name: ev.name, value: ev.value,
                              descriptionText: "${childDevice.displayName} ${ev.text}"]
                  if (ev.isStateChange) args.isStateChange = true
                  childDevice.sendEvent(args)
                }
                if (plan.alert) log.info "Abode: ${childDevice.displayName} ${plan.alert}"
                if (plan.reset)
                  runIn(plan.delay ?: 60, plan.reset, [data: ["cid": json_data.device_id], overwrite: false])
              }
            } else {
              if (childlessEventIsNotable(json_data, kind))
                log.warn "Abode sent an event for a device with no child in Hubitat: ${describeEvent(json_data, kind, action)} -- save preferences to create missing children"
              else if (logDebug)
                log.debug "Got event for a device with no child: ${redact(json_data)}"
            }
          }
        }

        // Abode sends is_alarm as the string "1", so this integer comparison
        // was never true and a panic alarm produced nothing but a debug line
        // that nobody had enabled.  An alarm is the single event this driver
        // exists for: it is logged unconditionally and published as an
        // attribute so a rule can subscribe to it.  Checked outside the
        // child-device block because the alarming device is often the keypad
        // or the hub, neither of which has a child.
        if ((is_alarm != null && is_alarm.toString() == '1') || action.contains('panic')) {
          log.warn "Abode ALARM: ${json_data.event_name} (device '${json_data.device_name}', code ${event_code})"
          sendEvent(name: 'lastAlarm', value: alert_value, descriptionText: message, isStateChange: true, type: 'Alarm')
        }

        // Abode puts hasFaults on every timeline event, but it only means
        // anything on the arm and disarm ones: "armed with the garage door
        // open" was invisible to Hubitat.
        //
        // Matched with a word-boundary regex rather than on device_type or on
        // a leading word, because neither survives contact with the real
        // events.  Arming from the keypad arrives as device_type Keypad while
        // arming from the phone arrives as the Panel, and the two fields
        // Abode sends word it differently: event_type says "Hub Armed w/
        // Faults(s) - Home" while event_name_v2, which timelineAction
        // rightly prefers, says "System armed with faults (Home)".  The word
        // boundary is what stops "Panic Alarm" and "Alarm Disabled" matching
        // on the "arm" inside "alarm".
        // 'arming' is the exit-timer event; 'armed' and 'disarmed' are the
        // terminal ones.  Abode has been seen sending hasFaults:"0" on an
        // arming event (event_code 6061) while a sensor really was faulted,
        // which cleared this attribute for the nine seconds until the armed
        // event put it back.  An exit-timer event may therefore raise the
        // flag but never lower it; only a terminal event clears it.  Abode
        // has also been seen holding a timeline event for 39 seconds, so that
        // window is not reliably short.
        def disarming = (action =~ /\bdisarm(ed|ing)\b/).find()
        def arming    = (action =~ /\barming\b/).find()
        def armed     = (action =~ /\barmed\b/).find()
        if (json_data.hasFaults != null && (arming || armed || disarming)) {
          // Faulted sensors mean nothing once the system is disarmed, so a
          // disarm always clears this regardless of what Abode reports.
          def faulted  = (!disarming && json_data.hasFaults.toString() != '0') ? 'true' : 'false'
          def mayClear = disarming || armed
          if ((faulted == 'true' || mayClear) && device.currentValue('armedWithFaults') != faulted) {
            sendEvent(name: 'armedWithFaults', value: faulted, descriptionText: "Abode armedWithFaults is ${faulted}")
            if (faulted == 'true') log.warn "Abode system armed with faulted sensors: ${message}"
          }
        }
        break

      // Central monitoring settings.  Abode only sends these when one of them
      // is changed, so the attributes track the last change seen rather than
      // the state at startup.
      case 'cms.setting':
        parseCmsSetting(json_data)
        break

      case ~/^device\.update.*/:
        reply = doHttpRequest('GET','/api/v1/devices/'+message)
        if (logTrace) log.trace "reply: ${redact(reply)}"
        if ( reply != null && reply[0] != null ) updateChildFromDevice(reply[0])
        break
      default:
        noteUnhandledEventClass(event_class, message)
        break
    }
  } else {
    log.warn "Unparseable Abode event message: ${event_text}"
  }
}

// Dispatch table for timeline events on devices that have a child.  Pure
// string matching with no Hubitat calls in it, so it can be exercised against
// real captured event strings without a hub.
//
// Clearing words are tested before alarming ones throughout.  Abode sends
// "Smoke Cleared" and "Tamper Switch Restored", and a naive search for
// "smoke" or "tamper" in those would latch the sensor into its alarm state
// and leave it there.
//
// Returns null when nothing matched, which is what raises the warning in
// parseEvent: an event the driver cannot interpret means a sensor is showing
// the wrong state in Hubitat, and that has to be visible without debug on.
// Abode numbers its timeline events, and the four codes below are the only
// ones observed here whose meaning is confirmed by the event text that came
// with them, on more than one device:
//
//   1383 / 3383  tamper triggered / restored  -- genuine Contact ID (SIA DC-05)
//   5100 / 5101  contact opened / closed      -- Abode's own numbering
//
// Nothing else is listed.  Smoke, water, glass and the doorbell have never
// appeared with a code in any capture taken here, and inventing one risks
// colliding with a real code and mislabelling an alarm -- worse than the
// warning an unmatched event already raises.  Those stay on text alone.
//
// Codes are checked ahead of the text because Abode's wording has already
// changed once under this driver, when event_name_v2 appeared and replaced
// strings the matchers had been written against.  The numbers stayed put.
private deviceEventCodePlan(String kind, String event_code) {
  switch (event_code) {
    // Every child driver carries TamperAlert, so this is not gated on kind.
    case '1383':
      return [events: [[name: 'tamper', value: 'detected', text: 'tamper is detected']],
              alert: 'reports tampering']
    case '3383':
      return [events: [[name: 'tamper', value: 'clear', text: 'tamper is clear']]]

    // Only the contact child exposes a contact attribute.  A different kind
    // of sensor sending these would fall through to the text table rather
    // than have an attribute it does not have written to it.
    case '5100':
      return (kind == 'contact') ? [events: [[name: 'contact', value: 'open',   text: 'is open']]] : null
    case '5101':
      return (kind == 'contact') ? [events: [[name: 'contact', value: 'closed', text: 'is closed']]] : null

    default:
      return null
  }
}

private deviceEventPlan(String kind, String action, String event_code = '') {
  def coded  = deviceEventCodePlan(kind, event_code ?: '')
  if (coded != null) return coded

  def act    = (action ?: '').toLowerCase()
  def clears = act.contains('clear') || act.contains('restore') || act.contains('normal')

  // Tamper is reported on every kind of sensor and says nothing about what
  // that sensor normally measures, so it is matched before the per-kind
  // table.  The GLASS branch used to fire shock=detected for every event it
  // received, which meant "Tamper Switch Restored" raised a false glass-break
  // alarm -- the opposite of what the event said.
  if (act.contains('tamper')) {
    def tampered = clears ? 'clear' : 'detected'
    return [events: [[name: 'tamper', value: tampered, text: "tamper is ${tampered}"]],
            alert: clears ? null : 'reports tampering']
  }

  switch (kind) {
    case 'contact':
      if (act.contains('close')) return [events: [[name: 'contact', value: 'closed', text: 'is closed']]]
      if (act.contains('open'))  return [events: [[name: 'contact', value: 'open',   text: 'is open']]]
      return null

    case 'smoke':
      if (clears)
        return [events: [[name: 'smoke', value: 'clear', text: 'is clear']]]
      if (act.contains('alarm') || act.contains('smoke'))
        return [events: [[name: 'smoke', value: 'detected', text: 'is detected']],
                alert: 'reports smoke', reset: 'smokeClear', delay: smokeClearDelay()]
      return null

    case 'water':
      if (clears || act.contains('dry'))
        return [events: [[name: 'water', value: 'dry', text: 'is dry']]]
      // 'leak' and 'flood' are guesses at wording never observed here; the
      // warning above is what will report the real string if they are wrong.
      if (act.contains('detect') || act.contains('wet') || act.contains('leak') || act.contains('flood'))
        return [events: [[name: 'water', value: 'wet', text: 'is wet']],
                alert: 'reports water']
      return null

    case 'doorbell':
      if (act.contains('press') || act.contains('push') || act.contains('ring') || act.contains('button'))
        return [events: [[name: 'button', value: 'pushed', text: 'is pushed'],
                         [name: 'pushed', value: 1, isStateChange: true, text: 'button 1 was pushed']],
                alert: 'was pressed', reset: 'doorbellOff', delay: 60]
      return null

    case 'glass':
      // No clear event has ever been observed from Abode for a glass break,
      // so the scheduled reset is still what restores it.
      if (clears)
        return [events: [[name: 'shock', value: 'clear', text: 'is clear']]]
      if (act.contains('glass') || act.contains('break') || act.contains('shock') || act.contains('alarm'))
        return [events: [[name: 'shock', value: 'detected', text: 'is detected']],
                alert: 'reports breaking glass', reset: 'glassClear', delay: 60]
      return null

    case 'motion':
    case 'multisensor':
      // Driven entirely by the device.update records, which carry the real
      // sensor state and the sensor's own occupancy timer.  A timeline event
      // for these is redundant rather than unhandled, so return an empty plan
      // instead of null: null is what raises the warning, and a motion sensor
      // in a busy room would turn that into a flood.
      return [events: []]

    default:
      return null
  }
}

// Named fields only.  These two warnings are written to be pasted into a
// public bug report, and a whole timeline payload carries the gateway MAC
// address, the account holder's name and whoever triggered the event.
// event_code is a Contact ID / SIA numeric and is the most stable thing in
// the record: Abode renames the English strings, not the codes.
private describeEvent(Map json_data, String kind, String action) {
  return "kind='${kind}' action='${action}' event_code='${json_data?.event_code}'" +
         " event_name_v2='${json_data?.event_name_v2}' device_type='${json_data?.device_type}'" +
         " type_tag='${json_data?.type_tag}' device='${json_data?.device_name}'"
}

// The hub itself sends a timeline event on every arm and disarm with an empty
// device_id, and keypads and remote controllers have no child driver in this
// package at all, so finding no child for those is expected.  Anything else
// means Abode has a sensor that Hubitat never got a child device for, which
// is worth saying out loud because that sensor silently does nothing.
private childlessEventIsNotable(Map json_data, String kind) {
  def id = json_data?.device_id?.toString() ?: ''
  if (id.isEmpty()) return false
  if (kind == 'keypad' || kind == 'remote') return false
  return true
}

// An event class the driver has never seen is the only hint that Abode has
// added something.  Warned once per class so that a chatty new class cannot
// flood the log, with a running count kept in state for whoever reports it.
private noteUnhandledEventClass(String event_class, String message) {
  def seen  = state.unhandledEventClasses ?: [:]
  def count = (seen[event_class] ?: 0) + 1
  seen[event_class] = count
  state.unhandledEventClasses = seen

  if (count == 1)
    log.warn "Abode sent an event class this driver does not handle: '${event_class}' -- please report this line"
  else if (logDebug)
    log.debug "Ignoring event ${event_class} ${message}"
}

// Central monitoring settings, pushed over the websocket when one of them is
// changed in the Abode app.  testModeActive is the one that matters: while it
// is on the monitoring centre will not dispatch, which is exactly the state
// you do not want to discover after the fact.  The dispatch toggles are
// reference state rather than something to write rules against, so they are
// data values.  Only fields actually present are stored -- dispatchMedical
// did not exist in earlier payloads.
private parseCmsSetting(Map settings) {
  if (settings == null || settings.isEmpty()) return

  ['monitoringActive', 'testModeActive'].each { field ->
    if (settings.containsKey(field)) {
      def value = settings[field].toString()
      if (device.currentValue(field) != value)
        sendEvent(name: field, value: value, descriptionText: "Abode ${field} is ${value}", type: 'Monitoring')
    }
  }

  ['sendMedia', 'dispatchPolice', 'dispatchFire', 'dispatchMedical', 'dispatchWithoutVerification'].each { field ->
    if (settings.containsKey(field)) updateDataValue(field, settings[field].toString())
  }

  if (settings.containsKey('testModeActive')) {
    if (settings['testModeActive'].toString() == 'true')
      log.warn 'Abode is in monitoring test mode: the monitoring centre will not dispatch'
    else if (logInfo)
      log.info 'Abode monitoring test mode is off'
  }
  if (settings['monitoringActive'] != null && settings['monitoringActive'].toString() != 'true')
    log.warn 'Abode professional monitoring is not active'
}

// Trace and debug dumps of whole Abode payloads are the most useful thing in
// a bug report and the most dangerous thing to ask a stranger to paste: the
// login response carries a live bearer token and the user record carries the
// account holder's name, address, coordinates, phone number, email and the
// central monitoring dispatch passcode.  Keys and structure are kept so the
// shape of the payload is still readable; the values are replaced.  The
// marker is in square brackets because Hubitat renders its log pane as HTML
// and silently swallows anything that looks like a tag: an angle-bracketed
// marker came out as an empty field, which reads as "Abode sent nothing
// here" rather than "this was removed".
private redact(data) {
  def secret = ['cms_code', 'address', 'address_line_2', 'city', 'state', 'zip',
                'latitude', 'longitude', 'phone', 'phone_number', 'email',
                'first_name', 'last_name', 'profile_pic', 'mac',
                'access_token', 'refresh_token', 'token', 'password',
                'user_name', 'user_id', 'event_by', 'mobile_name', 'pin_code_user']

  if (data instanceof Map)
    return data.collectEntries { key, value ->
      [(key): secret.contains(key.toString().toLowerCase()) ? '[redacted]' : redact(value)]
    }
  if (data instanceof List)
    return data.collect { item -> redact(item) }
  return data
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
      if (logTrace) log.trace "${kind} device record: ${redact(dev)}"
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
      state.webSocketOpenedAt = now()
      // A successful open cancels any reconnect queued by the close that came
      // before it.  Without this the scheduled connect fired regardless,
      // displaced the socket that had just come up, and that socket's close
      // queued the next one: a tear-down and rebuild every 120 seconds, which
      // dropped live events until the following reconnect replayed them.
      unschedule('connectEventSocket')
		  break

    case ~/^status: closing.*$/:
      // Opening a socket closes the one it replaces, so a close arriving
      // just after an open belongs to the displaced socket rather than the
      // live one.  Acting on it would mark a working connection as down and
      // queue a reconnect that breaks it.  Falling through to the check below
      // is safe because webSocketConnected is left true.
      if (socketCloseIsStale()) {
        if (logDebug) log.debug 'Ignoring close of an Abode event socket that has already been replaced'
        break
      }
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
