
all: draft-jennings-moq-secure-objects.txt draft-jennings-moq-secure-objects.html

clean:
	rm -f  draft-jennings-moq-secure-objects.txt  draft-jennings-moq-secure-objects.xml


draft-jennings-moq-secure-objects.html: draft-jennings-moq-secure-objects.xml
	xml2rfc draft-jennings-moq-secure-objects.xml --html  > draft-jennings-moq-secure-objects.html


draft-jennings-moq-secure-objects.txt: draft-jennings-moq-secure-objects.xml
	xml2rfc draft-jennings-moq-secure-objects.xml --text  > draft-jennings-moq-secure-objects.txt


draft-jennings-moq-secure-objects.xml: draft-jennings-moq-secure-objects.md
	kramdown-rfc draft-jennings-moq-secure-objects.md  > draft-jennings-moq-secure-objects.xml


