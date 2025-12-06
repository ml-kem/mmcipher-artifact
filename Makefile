#	Makefile

clean:
	$(RM) -f $(XBIN) $(OBJS)
	cd mmCipher-c && $(MAKE) clean
	cd mmCipher-py && $(MAKE) clean
	cd mmCipher-pkzk && $(MAKE) clean
	cd pr-fail-dec && $(MAKE) clean
	cd OracleMLWE-attack && $(MAKE) clean

