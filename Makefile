CA65=ca65
CL65=cl65
LD65=ld65
SIM65=sim65

all: sha256 sha256test

sha256test: sha256.s tests.s
	$(CL65) -o $@ -t sim6502 -C sim6502.cfg $^

sha256.prg: sha256.s main.c
	$(CL65) -o $@ -t c64 -C c64_local.cfg -u __EXEHDR__ $^

sha256: sha256.s main.c
	$(CL65) -o $@ -t sim6502 -C sim6502.cfg $^

test: sha256test
	$(SIM65) -v -c $< || (echo "FAILED TEST: $$?"; exit 1) && echo "ALL PASS"

clean:
	rm -f sha256 sha256.prg sha256test *.o
