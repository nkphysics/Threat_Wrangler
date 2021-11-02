# Threat Wrangler CHANGELOG

NOTE: Each commit is not necessarily a version change. Therefore, a new version have many changes from multiple dates. 
Please see the following logged changes.

### v0.1.3

* Added ThreatFox API to pull all IOCs added in the last 24 hrs.
* Changed usage to command line appliaction with input 2 input arguments "command" and "source"
* Cleaned duplicate writeout code by adding the universal writeout function

### v0.1.2

* Fixed issue where logged OTX pulses weren't being cross-referenced for duplicates/
* Changed time structure for IOC file writeout so that it would be compatable with windows

### v0.1.1

* Fixed log IOC pull issue by restricting the pull to just the first page
* Added README.md
* Added Lisense
* First Push to github/gitlab

### v0.1

* Initial code that pulls subscribed pulses from Alienvault OTX
