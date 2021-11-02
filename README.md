
# Threat Wrangler

A program that pulls and records indicators of compromise (IOCs) from a user's subscriptions from the Alien Vault Open Threat Exchange. Future work on this project hopes to bring other threat exchange api integration, further IOC researching, and the ability to issue scans of endpoints and network traffic.
=======
A program that pulls and records indicators of compromise (IOCs) from a user's subscriptions from the Alien Vault Open Threat Exchange.


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

1. Go to Alien Vault (https://otx.alienvault.com/) and create an account


2. While on Alien Vault, selects users and/or pulses to subscribe to. This is where the IOCs are going to be pulled from. 
	
	* It is recommended that for first time use you do not select too many pulses or users to subscribe to as this can lead to your first use taking quite a while.

3. After creating an account on Alien Vault, collect your api key. After signing in to Threat Fox collect that api key also.

4. Upon first running Threat Wrangler you will be prompted to enter in your api keys before IOC retrevial.

	In the terminal you will see the following:
	``Enter API KEY for https://otx.alienvault.com/api/v1:>``
	and
	``Enter API KEY for https://threatfox-api.abuse.ch/api/v1/:>``

5. If you entered in you api key in correctly, then the pulses you subscribed to will begin to be pulled.

## Usage

``python3 threat_wrangler.py (command) (source)``

* Currently the only command is ``pull`` and the only sources available are ``av`` for Alien Vault and ``tf`` for Threat Fox 
=======
3. After creating an account, collect your api key

4. Run Threat wrangler from the threat wrangler directory with the following command
	
	`python3 threat_wrangler.py`
	
5. Upon first use you will be prompted to paste in your api key for Alien Vault. Paste your api key in.

6. If you entered in you api key in correctly, then the pulses you subscribed to will begin to be pulled.

7. After a pulse is pulled, and it's IOCs have been stored you will be prompted to enter a tag for the IOCs that were retreived from a given pulse. Enter a tag for those IOCs. (A first run will take a while)

8. Run threat wrangler any other time and as new pulses with new IOCs are published to Alien Vault you will be able to pull and store them.

