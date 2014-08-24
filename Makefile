all:		./src/Makefile
		cd ./src; make; cd ../

install:	./src/Makefile
		cd ./src; make install; cd ../

uninstall:	./src/Makefile
		cd ./src;make uninstall; cd ../

clean:		./src/Makefile
		cd ./src; make clean; cd ../
