# SSCPOE/STEAMEMO Home Assistant Integration

<p align="center">
  <a href="https://github.com/slydiman/sscpoe/releases"><img src="https://img.shields.io/github/v/release/slydiman/sscpoe?display_name=tag&include_prereleases&sort=semver" alt="Current version"></a>
  <img alt="GitHub" src="https://img.shields.io/github/license/slydiman/sscpoe">
  <img alt="GitHub manifest.json dynamic (path)" src="https://img.shields.io/github/manifest-json/requirements/slydiman/sscpoe%2Fmain%2Fcustom_components%2Fsscpoe?label=requirements">
  <img alt="Total lines count" src="https://tokei.rs/b1/github/slydiman/sscpoe"
</p>

<img align="right" src="https://github.com/slydiman/sscpoe/blob/main/logo.png?raw=true" alt="Logo"/>

Unofficial SSCPOE/STEAMEMO integration for Home Assistant to control cloud-managed POE switches 4/8/16.

[Amazon](https://www.amazon.com/stores/STEAMEMO/page/77A8B3BC-CC6D-49F8-B191-49E312082D49)

[AliExpress](https://aliexpress.com/item/32849723315.html)

<img src="https://github.com/slydiman/sscpoe/blob/main/devices.png?raw=true" width="300" alt="Devices"/>

Tested with SSC-PS308G.

# Installation

### Option 1: [HACS](https://hacs.xyz/) Link

1. Click [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=slydiman&repository=https%3A%2F%2Fgithub.com%2Fslydiman%2Fsscpoe&category=Integration)
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

This integration requires using your SSCPOE account `email` and `password`. Use official SSCPOE from [Google Play](https://play.google.com/store/apps/details?id=com.sscee.app.sscpoe) or [App Store](https://apps.apple.com/us/app/sscpoe/id1555401398) to register account and devices.

[![Open your Home Assistant instance and show an integration.](https://my.home-assistant.io/badges/integration.svg)](https://my.home-assistant.io/redirect/integration/?domain=sscpoe)

# Usage

This integration exposes power sensors and POE control switches. 
