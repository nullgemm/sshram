NAME = sshram
CC = gcc
FLAGS = -std=c99 -pedantic -g
FLAGS+= -Wall -Wno-unused-parameter -Wextra -Werror=vla -Werror
VALGRIND = --show-leak-kinds=all --track-origins=yes --leak-check=full
CACHEGRIND = --tool=cachegrind --branch-sim=yes

#CMD = ./$(NAME) -e ../ssh/id_ed25519.pub ../ssh/id_ed25519.pub.chachapoly
CMD = ./$(NAME) ../ssh/id_ed25519

BIND = bin
OBJD = obj
SRCD = src
SUBD = sub
TESTD = tests

INCL = -I$(SRCD)
INCL+= -I$(SUBD)/ctypes
INCL+= -I$(SUBD)/argoat/src
INCL+= -I$(SUBD)/chrono/src
INCL+= -I$(SUBD)/cifra/src
INCL+= -I$(SUBD)/dragonfail/src
INCL+= -I$(SUBD)/testoasterror/src
INCL+= -I$(SUBD)/phc-winner-argon2/include

FINAL = $(SRCD)/main.c

TESTS = $(TESTD)/main.c
TESTS+= $(SUBD)/testoasterror/src/testoasterror.c

SRCS = $(SRCD)/sshram.c
SRCS+= $(SUBD)/argoat/src/argoat.c
SRCS+= $(SUBD)/chrono/src/chrono_posix.c
SRCS+= $(SUBD)/cifra/src/chacha20poly1305.c
SRCS+= $(SUBD)/cifra/src/chacha20.c
SRCS+= $(SUBD)/cifra/src/poly1305.c
SRCS+= $(SUBD)/cifra/src/blockwise.c
SRCS+= $(SUBD)/dragonfail/src/dragonfail.c
SRCS+= $(SUBD)/phc-winner-argon2/libargon2.a

FINAL_OBJS:= $(patsubst %.c,$(OBJD)/%.o,$(FINAL))
SRCS_OBJS := $(patsubst %.c,$(OBJD)/%.o,$(SRCS))
TESTS_OBJS:= $(patsubst %.c,$(OBJD)/%.o,$(TESTS))

LINK = -lpthread

# aliases
.PHONY: final
final: $(BIND)/$(NAME)
tests: $(BIND)/tests

# generic compiling command
$(SUBD)/phc-winner-argon2/libargon2.a:
	@echo "building $@"
	@cd $(SUBD)/phc-winner-argon2 && make

$(OBJD)/%.o: %.c
	@echo "building object $@"
	@mkdir -p $(@D)
	@$(CC) $(INCL) $(FLAGS) -c -o $@ $<

# final executable
$(BIND)/$(NAME): $(SRCS_OBJS) $(FINAL_OBJS)
	@echo "compiling executable $@"
	@mkdir -p $(@D)
	@$(CC) -o $@ $^ $(LINK)

run:
	@cd $(BIND) && $(CMD)

# tests executable
$(BIND)/tests: $(SRCS_OBJS) $(TESTS_OBJS)
	@echo "compiling tests"
	@mkdir -p $(@D)
	@$(CC) -o $@ $^ $(LINK)

check:
	@cd $(BIND) && ./tests

# tools
leak: leakgrind
leakgrind: $(BIND)/$(NAME)
	@rm -f valgrind.log
	@cd $(BIND) && valgrind $(VALGRIND) 2> ../valgrind.log $(CMD)
	@less valgrind.log

leakcheck: leakgrindcheck
leakgrindcheck: $(BIND)/tests
	@rm -f valgrind.log
	@cd $(BIND) && valgrind $(VALGRIND) 2> ../valgrind.log $(CMD)
	@less valgrind.log

cache: cachegrind
cachegrind: $(BIND)/$(NAME)
	@rm -f cachegrind.log
	@cd $(BIND) && valgrind $(CACHEGRIND) 2> ../cachegrind.log $(CMD)
	@less cachegrind.log

cachecheck: cachegrindcheck
cachegrindcheck: $(BIND)/tests
	@rm -f cachegrind.log
	@cd $(BIND) && valgrind $(CACHEGRIND) 2> ../cachegrind.log $(CMD)
	@less cachegrind.log

clean:
	@echo "cleaning"
	@rm -rf $(BIND) $(OBJD) valgrind.log cachegrind.log
	@cd $(SUBD)/phc-winner-argon2 && make clean

remotes:
	@echo "registering remotes"
	@git remote add github git@github.com:nullgemm/$(NAME).git
	@git remote add gitea ssh://git@git.nullgemm.fr:2999/nullgemm/$(NAME).git
