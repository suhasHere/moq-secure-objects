
all: draft-ietf-moq-secure-objects-00.txt  draft-ietf-moq-secure-objects-00.html

clean:
	rm -f draft-ietf-moq-secure-objects-00.txt \
		draft-ietf-moq-secure-objects-00.html \
		draft-ietf-moq-secure-objects-00.xml

draft-ietf-moq-secure-objects-00.xml: draft-ietf-moq-secure-objects.md
	kramdown-rfc -3 draft-ietf-moq-secure-objects.md > draft-ietf-moq-secure-objects-00.xml

draft-ietf-moq-secure-objects-00.txt: draft-ietf-moq-secure-objects-00.xml
	xml2rfc  draft-ietf-moq-secure-objects-00.xml --text >  draft-ietf-moq-secure-objects-00.txt

draft-ietf-moq-secure-objects-00.html: draft-ietf-moq-secure-objects-00.xml
	xml2rfc  draft-ietf-moq-secure-objects-00.xml --html >  draft-ietf-moq-secure-objects-00.html

