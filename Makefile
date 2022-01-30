all:
	ln -s socketClient.py client
	chmod +x client
clean:
	rm -rf __pycache__
	rm client