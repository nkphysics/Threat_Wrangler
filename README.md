
# Threat Wrangler

A program that pulls and records indicators of compromise (IOCs) from a user's subscriptions from the Alien Vault Open Threat Exchange and Threat Fox by abuse.ch.


## Dependent Libraries

1. pandas
2. argparse
3. json
4. os
5. requests
6. datetime
7. pathlib

## First Use Tasks

1. Go to Alien Vault (https://otx.alienvault.com/) and create an account

2. Go to Threat Fox (https://threatfox.abuse.ch/) and sign in with your twitter account. Make one if you do not have one.

## Basic Usage

``python3 threat_wrangler.py (command) (source)``

###Notes
 * The first time you run Threat Wrangler you will be prompted to enter in your api keys.
 * You can type in Alienvault and ThreatFox fully as the source or you can simply type av for Alienvault and tf for ThreatFox.
 * Currently the only command supported is pull, to pull IOCs
 * All IOCs will be stored in IOCs/
