MAKEFLAGS += --no-builtin-rules

.DELETE_ON_ERROR:
.SILENT:
.SECONDEXPANSION:

CFLAGS := -std=c11 -Wall -Wextra -Wshadow -Wdeclaration-after-statement -Wno-multichar -Werror -O2

ifdef TEST_DEBUG
CFLAGS += -DTEST_DEBUG=$(TEST_DEBUG)
endif

generated := syscall_lookup.c
executables := fake_xattr do_syscall
tests := test_xattr_db test_seccomp_unotify

xattr_db_objects := xattr_db.o zalloc.o
seccomp_unotify_objects := seccomp_unotify.o clone_vfork.o syscall_lookup.o
test_objects := mem_account.o fd_account.o child_account.o

fake_xattr_objects := main.o mem_account.o $(seccomp_unotify_objects) $(xattr_db_objects)
do_syscall_objects := do_syscall.o syscall_lookup.o zalloc.o

test_xattr_db_objects := test_xattr_db.o $(xattr_db_objects) $(test_objects)
test_seccomp_unotify_objects := test_seccomp_unotify.o $(seccomp_unotify_objects) $(test_objects)

objects := $(foreach executable,$(executables) $(tests),$($(executable)_objects))
uniq_objects :=
$(foreach object,$(objects),$(if $(filter $(object),$(uniq_objects)),,$(eval uniq_objects += $(object))))

outputs := $(generated) $(objects) $(executables) $(tests)

.PHONY: all clean test $(addprefix @,$(tests))

all: $(executables)

clean:
	echo rm $(outputs)
	rm -rf "$$(readlink .tmp)"
	rm -f $(outputs) .tmp

@test_seccomp_unotify: do_syscall .tmp .tmp/chroot

define test_target
@$(1): $(1)
	unshare --map-root-user --map-auto ./$$<
endef

$(foreach test,$(tests),$(eval $(call test_target,$(test))))

test: integration_test $(addprefix @,$(tests)) all .tmp
	./$<

$(foreach object,$(filter-out $(generated),$(objects:.o=.c)),$(eval $(shell $(CC) -MM $(object) | tr -d '\\')))

.tmp:
	echo MKTEMP $@
	ln -sf "$$(mktemp -d)" $@

.tmp/chroot: test_chroot_import_bin do_syscall | .tmp
	[ -e $@ ] || mkdir $@
	./$< $@ $(wordlist 2,$(words $^),$^) $$(command -v sh) $$(command -v cat) $$(command -v head) $$(command -v tail)

$(executables) $(tests): %: $$($$@_objects)
	echo LINK $^ '->' $@
	$(CC) $(CFLAGS) -o $@ $^

$(generated): %.c: gen_%
	echo GEN $@
	CC=$(CC) ./$< > $@

$(uniq_objects): %.o: %.c
	echo CC $< '->' $@
	$(CC) $(CFLAGS) -o $@ -c $<
