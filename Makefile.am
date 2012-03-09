ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdessert.pc

include doc/doxygen-include.am

DISSECTORS = dissectors/dessert.lua dissectors/dessert-ext-eth.lua dissectors/dessert-ext-ping.lua dissectors/dessert-ext-trace.lua
MIBS = doc/DESSERT-MIB.txt
DOCS = doc/libdessert.doxyfile doxygen/html doc/*.doxygen doc/style/*.css doc/style/*.html doc/style/images/*.png doc/style/images/*.gif doc/style/images/*.eps 
EXTRA_DIST = autogen.sh $(DOCS) $(MIBS) $(DISSECTORS)

install-data-local: install-mibs install-dissectors

install-mibs: installdirs-mibs
	if [ $(install_mibs) -eq 1 ]; then \
		for i in $(MIBS) ; do \
			$(INSTALL_DATA) $$i $(DESTDIR)/$(with_mibsdir) ; \
		done ; \
	fi

uninstall-mibs:
	for i in $(MIBS) ; do \
		rm -f $(with_mibsdir)/$$i ; \
	done

installdirs-mibs:
	if [ $(install_mibs) -eq 1 ]; then \
		$(MKDIR_P) $(DESTDIR)/$(with_mibsdir) ; \
	fi
	
install-dissectors: installdirs-dissectors
	if [ $(install_dissectors) -eq 1 ]; then \
		for i in $(DISSECTORS) ; do \
			$(INSTALL_DATA) $$i $(DESTDIR)/$(with_dissectorsdir) ; \
		done ; \
	fi

uninstall-dissectors:
	for i in $(DISSECTORS) ; do \
		rm -f $(with_dissectorsdir)/$$i ; \
	done

installdirs-dissectors:
	if [ $(install_dissectors) -eq 1 ]; then \
		$(MKDIR_P) $(DESTDIR)/$(with_dissectorsdir) ; \
	fi
