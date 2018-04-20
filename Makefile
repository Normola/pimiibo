all: pimiibo pimiiboEmu.c amiitoolsubmodule

pimiibo: pimiibo.c
	gcc pimiibo.c -o pimiibo -lnfc

pimiiboEmu: pimiiboEmu.c
	gcc pimiiboEmu.c -o pimiiboEmu -lnfc

amiitoolsubmodule:
	cd amiitool && $(MAKE) amiitool

clean:
	rm pimiibo
	cd amiitool && $(MAKE) clean
