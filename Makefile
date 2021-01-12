port=9000
url=127.0.0.1:$(port)
default:: run

SHELL := /bin/bash

run:
	#./manage.py runsslserver $(url)
	./make.py
open:
	firefox --private https://$(url)
install:
	pip install virtualenv
	virtualenv env
enter:
	source ./env/bin/activate
exit:
	deactivate
