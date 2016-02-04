
dep: sfood.dot
	dot -Tps -Nfontsize=200 -Nheight=10 -Nwidth=10 -Earrowsize=20 -Gnodesep=0 < sfood.dot >sfood.ps

sfood.dot: sfood.out
	sfood-graph < sfood.out > sfood.dot

sfood.out:
	sfood --internal > sfood.out

clean:
	rm -rf sfood.ps
	rm -rf sfood.dot
	rm -rf sfood.out
	rm -rf tests/htmlcov
	rm -rf tests/.coverage
	rm -rf *.jpg
	rm -rf *.ps
	rm -rf *.pdf
	rm -rf html
	find . -name "*.pyc" | xargs rm


cov:
	cd tests; coverage run ./testsuite.py
	cd tests; coverage html --omit "/usr/share/*"

count:
	find . -name "*.py" | xargs cat | sed '/^\s*$$/d' | wc -l

uml:
	pyreverse -ojpg -k  -pelements OpenPGP/elements.py
	pyreverse -ojpg -k -ppackets OpenPGP/packets.py
	pyreverse -ojpg -k -pmessages OpenPGP/messages.py
	pyreverse -ojpg -k -psubpackets OpenPGP/subpackets.py
	jpeg2ps classes_elements.jpg > classes_elements.ps
	jpeg2ps classes_packets.jpg > classes_packets.ps
	jpeg2ps classes_messages.jpg > classes_messages.ps
	jpeg2ps classes_subpackets.jpg > classes_subpackets.ps
	pyreverse -opdf -k  -pelements OpenPGP/elements.py
	pyreverse -opdf -k -ppackets OpenPGP/packets.py
	pyreverse -opdf -k -pmessages OpenPGP/messages.py
	pyreverse -opdf -k -psubpackets OpenPGP/subpackets.py


doc:
	epydoc -v --exclude openpgpdump blindca blinding crypto encoding idclient idserver keyserver OpenPGP
