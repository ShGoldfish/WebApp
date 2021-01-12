#!/usr/bin/python3
#https://www.piware.de/2011/01/creating-an-https-server-in-python/
#https://blog.anvileight.com/posts/simple-python-http-server/
#https://gist.github.com/toolness/3073310
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

import os,sys

from io import BytesIO

#for easy HTML
import dominate
from dominate.tags import *
from dominate.util import raw

import subprocess
import shlex

import datetime
import time

import getpass

cert=None
port=4443
url='localhost'
prefix='http://'
openssl = "openssl"
current_user = getpass.getuser()
log_file = './logs.txt'

openssl_dir = "/home/runner/openssl/apps"
if current_user == f"runner":
	openssl =f"{openssl_dir}/openssl"

def log(string, file=log_file):
	print(string)
	with open(file, 'a') as appender:
		appender.write(f"{string}\n")


key_exchange = {
	'Classic McEliece': [],
	'Kyber': [
		'kyber512','kyber768','kyber1024','kyber90s512','kyber90s768','kyber90s1024'
	],
	'NTRU': [
		'ntru_hps2048509', 'ntru_hps2048677', 'ntru_hps4096821', 'ntru_hrss701', 'ntrulpr653', 'ntrulpr761', 'ntrulpr857', 'sntrup653', 'sntrup761', 'sntrup857'
	],
	'SABER': [
		'lightsaber', 'saber', 'firesaber'
	]
}
auth = {
	'Dilithium':[
		'dilithium2', 'dilithium3', 'dilithium4'
	],
	'Falcon':[
		'falcon512', 'falcon1024'
	],
	'Rainbow':[
		'rainbowIaclassic', 'rainbowIacyclic', 'rainbowIacycliccompressed', 'rainbowIIIcclassic', 'rainbowIIIccyclic', 'rainbowIIIccycliccompressed', 'rainbowVcclassic', 'rainbowVccyclic', 'rainbowVccycliccompressed'
	],
}

class requestHandler(BaseHTTPRequestHandler):
	def generate_cert(self, string):
		running_output = []
		try:
			running_strings = [
				f"{openssl} req -x509 -new -newkey {string} -keyout {string}_CA.key -out certs/{string}_CA.crt -nodes -subj \"/CN=oqstest CA\" -days 365 -config {openssl_dir}/openssl.cnf",
				f"{openssl} genpkey -algorithm {string} -out {string}_srv.key",
				f"{openssl} req -new -newkey {string} -keyout {string}_srv.key -out {string}_srv.csr -nodes -subj \"/CN=oqstest server\" -config {openssl_dir}/openssl.cnf",
				f"{openssl} x509 -req -in {string}_srv.csr -out {string}_srv.crt -CA certs/{string}_CA.crt -CAkey {string}_CA.key -CAcreateserial -days 365"
			]
			cmds_file='commands.txt'
			os.system(f"touch {cmds_file}")
			with open(cmds_file, 'a') as appender:
				for x in running_strings:
					running_output += [self.capture_output(x)]
					appender.write(x)
					appender.write('\n')
		except:
			pass
		return running_output
	def capture_output(self, cmd):
		log(f"Running the command {cmd}")
		stdout, stderr = None, None
		try:
			proc = subprocess.Popen(
				shlex.split(cmd),
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				universal_newlines=True
			)

			stdout, stderr = proc.communicate()

		except Exception as e:
			log('Unknown Error ' + str(e))
			stderr = e

		if stdout:
			stdout = stdout.split('\n')
		return (stdout, stderr)
	def write_time(self, algo, time):
		log(f"Writing the Algorithm: {algo}")
		algo = algo.replace('.crt','')
		table = f"./tables/{algo}.csv"
		log(f"Writing the table: {table}")
		foil_type = "w"

		if os.path.exists(table):
			foil_type = "a"
		else:
			os.system(f"touch {table}")

		with open(table, foil_type) as foil:
			cur_date = datetime.datetime.now().strftime("%Y-%b-%d_%H:%M")
			foil.write(f"{cur_date}, {time}\n")
	def generate_table(self, box: dict):
		for key, value in box.items():
			with h3(key).add(table()).add(tbody()):
				tr().add(th('Algorithm Name')).add(th('Generate Certificate')).add(th('View Certificate')).add(th('Download Certificate')).add(
					th('View Table')).add(th('Download Table'))
				for x in value:
					cert = f"/certs/{x}_CA.crt"
					cert_row = "View Cert"
					download_cert_row = "Download Cert"

					table_file = f"/tables/{x}.csv"
					table_file_row = "View Result"
					download_table_file_row = "Download Table"

					if os.path.exists("."+cert):
						cert_row = a(cert_row, href=cert)
						download_cert_row = a(download_cert_row, href="/download"+cert)

					if os.path.exists("."+table_file):
						table_file_row = a(table_file_row, href=table_file)
						download_table_file_row = a(download_table_file_row, href="/download"+table_file)

					tr().add(td(x)).add(td(a('Generate Cert', href=f"/{x}"))).add(
						td(cert_row)).add(td(download_cert_row)).add(td(table_file_row)).add(td(download_table_file_row))
	def styling(self):
		with div(id='header'):
			raw_css = """
			* {
			  box-sizing: border-box;
			}

			.column {
			  float: left;
			  width: 50%;
			  padding: 5px;
			}

			/* Clearfix (clear floats) */
			.row::after {
			  content: "";
			  clear: both;
			  display: table;
			}

			table,th,td {
				border: 1px solid black;
			}
			"""
			style(raw_css)
	def view_cert(self, doc=None, url_path:str=None):
		with doc:
			self.styling()
			h1(f"Viewing the Document {url_path}")
			h2(a("Home", href="/"))

			(success, failure) = self.capture_output(f"{openssl} x509 -in {url_path} -text")
			with pre():
				if success and len(success) >= 0:
					check = 0
					for x in success:
						raw(x + "\n")
	def write_main(self, doc, url_path):
		with doc:
			self.styling()
			h1(f"Base Document {url_path}")
			with div(cls="row",style='{border: 3px solid;padding: 20px;}'):
				with div(cls="column"):#,style='{width: 50%;float: left;padding: 20px;	border: 2px solid red;}'):
					with h2('auth',id='auth_list'):
						self.generate_table(auth)
		
	def do_GET(self):
		url_path = self.path.replace("/", "",1)
		log(url_path)
		doc = dominate.document(title=f"Class Project")


		if url_path is None or url_path == "":
			self.send_response(200)
			self.end_headers()
			#with doc.head:
				#link(rel='stylesheet', href='style.css')
				#script(type='text/javascript', src='./js/brython.min.js')
			self.write_main(doc, url_path)

		elif url_path.startswith('favicon.ico'):
			self.send_response(200)
			self.end_headers()
		elif url_path.startswith('command'):
			self.send_response(200)
			self.end_headers()
			with doc:
				self.styling()
				h1(f"Viewing the curent commands that have run")
				h2(a("Home", href="/"))

				(success, failure) = self.capture_output(f"cat ./commands.txt")
				with pre():
					if success and len(success) >= 0:
						check = 0
						for itr, x in enumerate(success):
							raw(f"{itr}  | {x}\n")
		elif url_path.startswith('log'):
			self.send_response(200)
			self.end_headers()
			with doc:
				self.styling()
				h1(f"Viewing the curent log that have run")
				h2(a("Home", href="/"))

				(success, failure) = self.capture_output(f"cat {log_file}")
				with pre():
					if success and len(success) >= 0:
						check = 0
						for itr, x in enumerate(success):
							raw(f"{itr}  | {x}\n")
		elif os.path.exists(url_path):
			self.send_response(200)
			self.end_headers()
			if url_path.endswith('.csv'):
				with doc:
					self.styling()
					h1(f"Viewing the table {url_path}")
					h2(a("Home", href="/"))
					with h3('Results').add(table()).add(tbody()):
						tr().add(th('DateTime')).add(th('Total Time'))
						with open(url_path,'r') as csv:
							for line in csv.readlines():
								x,y = line.split(',')
								tr().add(td(x)).add(td(y))
			elif url_path.endswith('.pem') or url_path.endswith('.crt'):
				if url_path.count('.crt') == 2:
					url_path = url_path.replace('.crt.crt','.crt')
				self.view_cert(doc, url_path)
		elif url_path.startswith('download'):
			self.send_response(200)
			self.end_headers()
			foil = url_path.replace('download/','')
			full_file = None
			with open(foil,'r') as contents:
				full_file = contents.readlines()
			self.wfile.write(full_file.encode('utf-8'))
		else:
			algorithm = url_path

			t_begin = time.time()
			self.generate_cert(algorithm)
			t_end = time.time()

			if not algorithm.endswith('.crt'):
				algorithm = algorithm + '.crt'
			if algorithm.count('.crt') == 2:
				algorithm = algorithm.replace('.crt.crt','.crt')


			prefix = None
			if algorithm.startswith('certs/'):
				prefix, algorithm = 'certs/', algorithm.replace('certs/','')


			self.write_time(algorithm, str(t_end-t_begin))
			#self.view_cert(doc, 'certs/'+algorithm)

			if prefix:
				algorith = prefix + algorithm

			log(f"Setting the header as: {algorithm}")
			#self.send_response(301)
			#self.send_header('Location',algorithm)
			#self.end_headers()
			self.send_response(200)
			self.end_headers()
			self.write_main(doc, url_path)

						

		print(str(doc))
		self.wfile.write(str(doc).encode('utf-8'))
	def do_POST(self):
		content_length = int(self.headers['Content-Length'])
		body = self.rfile.read(content_length)
		self.send_response(200)
		self.end_headers()
		response = BytesIO()
		response.write(b'This is POST request. ')
		response.write(b'Received: ')
		response.write(body)
		self.wfile.write(response.getvalue())

if __name__ == '__main__':

	if current_user == f"runner" or True:
		url = '0.0.0.0'

	httpd = HTTPServer((url, port), requestHandler)

	if cert:
		httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert, server_side=True)
		prefix='https://'

	print(f"Please visit the website at {prefix}{url}:{str(port)}")

	httpd.serve_forever()

