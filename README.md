# SSCPOE/STEAMEMO Home Assistant Integration

<p align="center">
  <a href="https://github.com/slydiman/sscpoe/releases"><img src="https://img.shields.io/github/v/release/slydiman/sscpoe?display_name=tag&include_prereleases&sort=semver" alt="Current version" /></a>
  <img alt="GitHub" src="https://img.shields.io/github/license/slydiman/sscpoe" />
  <img alt="GitHub manifest.json dynamic (path)" src="https://img.shields.io/github/manifest-json/requirements/slydiman/sscpoe%2Fmain%2Fcustom_components%2Fsscpoe?label=requirements" />
</p>

<img align="right" src="https://github.com/slydiman/sscpoe/blob/main/logo.png?raw=true" alt="Logo"/>

Unofficial SSCPOE/STEAMEMO/Amitres IOT integration for Home Assistant to control managed POE switches 4/8/16.

[Amazon](https://www.amazon.com/stores/STEAMEMO/page/77A8B3BC-CC6D-49F8-B191-49E312082D49)

[AliExpress](https://aliexpress.com/item/32849723315.html)

<img src="https://github.com/slydiman/sscpoe/blob/main/devices.png?raw=true" width="300" alt="Devices"/>

Tested with GPS204, PS308G, GPS316, GS105.

Note the devices with the firmware version v6.0.231024 have no a WEB UI and the firmware cannot be updated.
The newer devices with the firmware version v6.0.24xxxx have the WEB UI and the firmware can be updated (if the manufacturer will publish the firmware).
All devices v6.0.xxxxxx work locally and via a cloud.

Note GS105 is the managed switch with 1 POE input. It has no POE outputs. You can only monitor the linkage.

Supported:
- Cloud account (required e-mail and the cloud password)
- Local UDP multicast protocol (old API, auto search for devices, default activation code is `123456`)
- Local WEB protocol (new API, required device's IP and the activation code)

# Installation

### Option 1: [HACS](https://hacs.xyz/) Link

1. Click [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=slydiman&repository=sscpoe&category=Integration)
2. Restart Home Assistant

### Option 2: [HACS](https://hacs.xyz/)

1. Or `HACS` > `Integrations` > `⋮` > `Custom Repositories`
2. `Repository`: paste the url of this repo
3. `Category`: Integration
4. Click `Add`
5. Close `Custom Repositories` modal
6. Click `+ EXPLORE & DOWNLOAD REPOSITORIES`
7. Search for `sscpoe`
8. Click `Download`
9. Restart _Home Assistant_

### Option 3: Manual copy

1. Copy the `sscpoe` folder inside `custom_components` of this repo to `/config/custom_components` in your Home Assistant instance
2. Restart _Home Assistant_

# Configuration

This integration supports the cloud and local management.
For the cloud management you need the SSCPOE account `email` and `password`. Use official SSCPOE app (Amitres IOT) from [Google Play](https://play.google.com/store/apps/details?id=com.sscee.app.sscpoe), [App Store](https://apps.apple.com/us/app/sscpoe/id1555401398) or [Windows desktop config app](http://www.sscee.com/en/en/col.jsp?id=105) to register account and devices.
For the local management (old UDP multicast protocol) you need the activation code (default `123456`). This integration will scan the local network for available devices automatically. The activation code may be changed in the official SSCPOE app.
For the local management using WEB protocol you need to know the IP address and the activation code.

[![Open your Home Assistant instance and show an integration.](https://my.home-assistant.io/badges/integration.svg)](https://my.home-assistant.io/redirect/integration/?domain=sscpoe)

# Usage

This integration exposes power sensors and POE control switches. You can also activate linkage sensors.

Note: The cloud server does not support multiple connections to the same account from Home Assistant and the SSCPOE app. If you are using the cloud management, the device in Home Assistant will disappear after connecting from the official SSCPOE app and will be reconnected within 30 seconds automatically. You can share the project in the official SSCPOE app to other account and use this account for this integration. The device settings in the SSCPOE app are available only for the admin account.

Note most devices with WEB UI do not support multiple logins. You must shutdown Home Assistant or delete the device entry in this integration and wait for some time or reboot the POE switch to login to WEB UI in a browser.

Note you can use WEB protocol in this intagration and the cloud management via iPhone/Android app simultaneously.
