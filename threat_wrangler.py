#!/usr/bin/env python

# Threat Wrangler
# Created by: nkphysics https://github.com/nkphysics
# License: Apache 2.0

# Dependent libraries
import pandas as pd
import argparse as ap
import os
import pathlib as pl
import requests
import json
import datetime as dt


class Threat_Wrangler(object):
	def __init__(self):
		store_stat = os.path.exists("store.csv")
		api_urls = [r"https://otx.alienvault.com/api/v1", r"https://threatfox-api.abuse.ch/api/v1/"]
		self.store = pd.read_csv("store.csv", index_col=None) if store_stat == True else pd.DataFrame({"URL":api_urls, "API_KEY":[0, 0]})
		self.pulses = []
		log_stat = os.path.exists("LOG.csv")
		self.log = pd.read_csv("LOG.csv") if log_stat == True else pd.DataFrame({"Title":[], "FILE_PATH":[], "Date Added":[]})

	def check_store(self):
		"""
		# Checks the API key store index for API Keys
		"""
		for i in self.store.index:
			if self.store.loc[i, "API_KEY"] == 0:
				print("No API KEY on record!")
				key_in = str(
					input("Enter API KEY for " + str(self.store.loc[i, "URL"]) + ":> ")
				)
				self.store.loc[i, "API_KEY"] = key_in
				self.store.to_csv("store.csv", index=False)
			else:
				pass
				
	def writeout(self, frame, name):
		ct = name
		base_dir = os.getcwd()
		date = dt.datetime.now()
		date_str = date.strftime("%Y-%m-%d_T%H%M%S")
		outpath = pl.Path(base_dir, str(ct) + str(date_str) + ".csv")
		frame.to_csv(outpath, index=False)
		print("IOC file written out at: " + str(outpath))
		nl = pd.Series(
			data=[
				ct + date_str,
				outpath,
				date_str,
			],
			index=["Title", "FILE_PATH", "Date Added"],
		)
		self.log = self.log.append(nl, ignore_index=True)
		self.log.to_csv("LOG.csv", index=False)

	def pullOTX(self):
		# Pulls all of the subscribed pulses for a user
		r = requests.get(
			self.store.loc[0, "URL"] + "/pulses/subscribed?page=1&limit=100",
			headers={"X-OTX-API-KEY": self.store.loc[0, "API_KEY"]},
		)
		pull0 = 0
		if r.status_code == 200:
			pull0 = r.text
		else:
			print("Issue in Retrieval from AlienVault")
		while pull0:
			print("*** Pulling Pulses ***")
			pulses = json.loads(pull0)
			if "results" in pulses:
				for i in pulses["results"]:
					pulse_title = i["name"]
					self.pulses.append(i)
				pull0 = None
				break  # Only here since there are so many IOCs being pulled that the actual pulling takes forever
			if "next" in pulses:
				if pulses["next"]:
					pull0 = requests.get(
						pulses["next"],
						headers={"X-OTX-API-KEY": self.store.loc[0, "API_KEY"]},
					).text
		for i in self.pulses:
			self.IOC_write(i)
		print("All IOCs Written and Logged")

	def pull_fox(self, time):
		# Pulls all IOCs from threatfox
		if time == None:
			time = 1
		else:
			pass
		print("Pulling ThreatFox IOCs")
		r = requests.post(
			self.store.loc[1, "URL"],
			headers={"X-API-TOKEN": ""},
			data=json.dumps({"query": "get_iocs", "days": time}),
		)
		pull0 = 0
		if r.status_code == 200:
			pull0 = r.text
		else:
			print("Issue with Retrieval from ThreatFox")
		load = json.loads(pull0)
		iocs = []
		tags = []
		for i in load["data"]:
			if i["ioc_type"] == "ip:port":
				ioc = i["ioc"].split(":")[0]
			else:
				ioc = i["ioc"]
			iocs.append(ioc)
			tags.append(i["malware_printable"])
		df = pd.DataFrame({"Indicator": iocs, "Tag": tags})
		self.writeout(df, "ThreatFox")
			
	def show_ps(self):
		# shows the pulses that were pulled (Currently not in use, but useful for future functionality)
		ioc_c = 0
		print("Retrieved Pulses: ")
		for i in self.pulses:
			title = i["name"]
			author = i["author_name"]
			created = i["created"]
			print(str(ioc_c) + ". " + str(title))
			print(" // Created:" + str(created))
			print(" // Author:" + str(author))
			ioc_c = ioc_c + 1

	def IOC_write(self, i):
		# Writes the IOC .csv files and updates the log file
		title = i["name"]
		tags = i["tags"]
		print("Pulse: " + str(title))
		iocs = []
		print("Suggested Tags: " + str(tags))
		for k in i["indicators"]:
			iocs.append(k["indicator"])
		ttags = []
		ct = str(input("Tag Name: "))
		while len(ttags) < len(iocs):
			ttags.append(ct)
		ioc_df = pd.DataFrame({"Indicator": iocs, "Tag": ttags})
		self.writeout(ioc_df, ttags[0])
		
	def pull(self, source, time):
		tw.check_store()
		av = ['otx', 'OTX', 'alienvault', 'AlienVault', 'av', 'AV']
		tf = ['threatfox', 'threat fox', 'ThreatFox', 'tf', 'TF']
		if source in av:
			tw.pullOTX()
		elif source in tf:
			tw.pull_fox(time)
		else:
			print("Source Not Found")
				
	def main(self):
		p = ap.ArgumentParser()
		p.add_argument("command", type=str)
		p.add_argument("source", type=str, nargs="?")
		p.add_argument("time_frame", type=int, nargs="?")
		args = p.parse_args()
		if args.command == "Pull" or args.command == "pull":
			self.pull(args.source, args.time_frame)
		else:
			print("Unknown Command: " + str(args.command))
			
	def cat_IOCs(self):
		log = self.log
		logged = len(log["Title"])
		for i in self.pulses:
			if logged == 0:
				self.IOC_write(i)
			else:
				for j in log["Title"]:
					if i == j:
						pass
					else:
						self.IOC_write(i)
		print("All IOCs Written and Logged")
		
if __name__ == "__main__":
	tw = Threat_Wrangler()
	tw.main()
