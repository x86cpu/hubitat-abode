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
 *  Original code: https://github.com/jorhett/hubitat-abode
 *
 */

 metadata {
  definition (
    name: 'Abode Alarm Doorbell',
    namespace: 'x86cpu',
    author: 'Eric Meddaugh',
    importUrl: 'https://raw.githubusercontent.com/x86cpu/hubitat-abode/master/drivers/AbodeDoorbell.groovy',
  ) {
    capability "Actuator"
    capability "PushableButton"
    // Legacy attribute, kept so existing rules kept working.  Rule Machine's
    // Button Device trigger only offers PushableButton / HoldableButton /
    // DoubleTapableButton, so this attribute was invisible there.
    attribute 'button', "ENUM", ["pushed", "released"]
    capability 'TamperAlert'
    // Reported by Abode on every device; see updateChildFaults() in the parent
    attribute 'lowBattery',  'ENUM', ['false', 'true']
    attribute 'bypassed',    'ENUM', ['false', 'true']
    attribute 'deviceFault', 'STRING'
  }
 }

// Hubitat standard methods
def installed() {
  log.debug 'installed'
  // Abode doorbells report a single button
  sendEvent(name: 'numberOfButtons', value: 1)
}

def uninstalled() {
  log.debug 'installed'
}

def updated() {
  if (device.currentValue('numberOfButtons') == null)
    sendEvent(name: 'numberOfButtons', value: 1)
}

// PushableButton. The parent raises this when Abode reports a button press.
// Exposing the command also makes the whole path testable without hardware,
// which matters because no Abode doorbell was available to test against.
def push(buttonNumber = 1) {
  def button = (buttonNumber ?: 1) as Integer
  sendEvent(name: 'pushed', value: button, isStateChange: true, descriptionText: "${device.displayName} button ${button} was pushed")
  sendEvent(name: 'button', value: 'pushed', descriptionText: "${device.displayName} is pushed")
  runIn(5, 'releaseButton')
}

def releaseButton() {
  sendEvent(name: 'button', value: 'released', descriptionText: "${device.displayName} is released")
}

def refresh() {
}
