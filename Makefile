all:
	+$(MAKE) -C checksum
	+$(MAKE) -C encryption
	+$(MAKE) -C test