#/*
# *
# * Copyright (C) 2003 s0ttle (pacman@sawbox.net)
# *
# * This program is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 2 of the License, or
# * (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# *
# *
# *****
# */

# VARIABLES
PROG	= arpview
HDR1	= ../include/arpview.h 
HDRS    = ${HDR1}
OBJ1	= arpview.o 
OBJS    = ${OBJ1} ${OBJ2}
WRN1    = -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wcast-align
WRN2    = -Wsign-compare
WARN    = ${WRN1} ${WRN2}
FLAGS	= ${WARN} -g3 -ggdb -pedantic -ansi -pg -p
CC	= gcc
INSDIR	= /usr/local/bin
CLEAN	= *.core core.* core


# TARGETS

all: $(PROG)

%.o: %.c
	$(CC) $(INCFLG) $(FLAGS) -c $<

$(OBJS): $(HDRS)

$(PROG): $(OBJS) ; $(CC)    -o $(PROG) $(OBJS) $(LIBS)\
	 $(FLAGS) ; /bin/ln -s src/arpview ../arpview

install:
	make && install -b -m 0755 -S -s -v $(PROG) $(INSDIR)

# PHONY TARGETS

.PHONY: clean

clean:
	rm -f $(PROG) $(OBJS) $(CLEAN)
