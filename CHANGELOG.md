# Changelog

All notable changes to this project from 2026-04-27 onward will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [5.0.0] - 2026-04-29

### Removed

* Removed support for authentication via the now deprecated OpenID 1.0 / OpenID 2.0 protocols.

## [4.1.3] - 2026-04-28

### Changed

* Updated the declaration of transitive dependency overrides so that they are exported to downstream dependencies. (#19)

## [4.1.2] - 2026-04-28

### Security

* Update transitive dependency on org.bouncycastle:bcprov-jdk18on to 1.84 to address dependabot-reported vulnerabilities.

## [4.0.0] - 2025-12-16

* Move from Java 11 to 21
* Update appbase dependency to 4.0.0
* Update derby 10.14 -> 10.17
* Move from javax.servlet -> jakarta.servlet 6.0

## [3.0.3] - 2025-07-24

* Update shiro to 1.13.0 to avoid most severe CVEs. Move to Shiro2.x would be breaking and there's no migration documentation.
* Update appbase dependency to pull in update to tomcat 9.0

