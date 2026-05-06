=== Simple Login History ===
Contributors: Jason Cox
Tags: login, history, audit, users
Requires at least: 5.8
Tested up to: 6.9.4
Requires PHP: 7.4
Stable tag: 1.2.7
License: GPL-2.0-or-later

Tracks WordPress login attempts, successful sessions, logout times, last seen timestamps, browser, OS, IP address, and user agent.

== Description ==

Simple Login History is a small local-only plugin for tracking user login activity without third-party services.

It records:

* User ID
* Username
* Role
* Browser
* Operating system
* IP address
* Timezone and country placeholders
* User agent
* Login time
* Logout time
* Last seen time
* Duration
* Login status
* Login source: WordPress or App
* Source filtering between WordPress and App logins
* App token status: Active, Expired, or Invalidated

The report is available in Users > Login History.

Options are available in Users > Login History Settings:

* Enable or disable WordPress login tracking
* Enable or disable AskBruno app login tracking
* Store or hide IP addresses
* Track only selected roles
* Auto logout idle users after a chosen number of minutes
* Auto delete old records after a chosen number of days
* Send email alerts for successful and failed logins
* Choose comma, semicolon, or tab as the CSV export separator

== Installation ==

1. Upload the `simple-login-history` folder to `wp-content/plugins/`.
2. Activate Simple Login History in WordPress.
3. Open Users > Login History.

== Notes ==

Country and timezone are intentionally left blank. Filling those fields accurately requires either a third-party GeoIP service or a local GeoIP database, which would add maintenance and privacy considerations.

== GitHub Updates ==

Automatic updates are powered by Plugin Update Checker and use the GitHub repository at https://github.com/jcjason12108-alt/simple-login-history.

If the repository is private, add a GitHub token with read access to the repository in wp-config.php:

`define( 'SLH_UPDATE_GITHUB_TOKEN', 'your-github-token' );`

== Changelog ==

= 1.2.7 =
* Added GitHub update support with Plugin Update Checker.
* Added optional private repository token support.
* Updated WordPress compatibility metadata.
