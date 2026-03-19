# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Docker build (Dockerfile.ipsec) now copies `third_party` so bundled pugixml is available; fixes "Cannot find source file third_party/pugixml/src/pugixml.cpp"
