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
    name: 'Abode Alarm MultiSensor',
    namespace: 'x86cpu',
    author: 'Eric Meddaugh',
    importUrl: 'https://raw.githubusercontent.com/x86cpu/hubitat-abode/master/drivers/AbodeMultiSensor.groovy',
  ) {
    capability 'Sensor'
    capability "RelativeHumidityMeasurement"
    capability "TemperatureMeasurement"
    capability "IlluminanceMeasurement"
    //capability 'Refresh'
    // humidity - NUMBER, unit:%rh
    // temperature - NUMBER, unit:°F || °C
    // illuminance - NUMBER, unit:lx
  } 
 }

// Hubitat standard methods
def installed() {
  log.debug 'installed'
}

def uninstalled() {
  log.debug 'installed'
}

def updated() {
}

def refresh() {
}
