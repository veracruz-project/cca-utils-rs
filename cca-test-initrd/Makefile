.PHONY: default
default: build

.PHONY: build
build: initrd.cpio

# STRIP = aarch64-linux-musl-strip
# STRIP = aarch64-none-elf-strip
# STRIP = aarch64-elf-strip
STRIP = aarch64-linux-gnu-strip

FEATURES ?= tsm,verbose

initrd.cpio: init
	rm -rf initrd initrd.cpio
	mkdir initrd
	cp target/aarch64-unknown-linux-musl/release/cca-test-initrd initrd/init
	$(STRIP) initrd/init
	(cd initrd ; echo init | cpio --create -V --format=newc -O ../initrd.cpio)
	rm -rf initrd

.PHONY: init
init:
	rustup target add aarch64-unknown-linux-musl
	cargo build --release --features $(FEATURES) --target aarch64-unknown-linux-musl

.PHONY: clean
clean:
	rm -rf initrd.cpio
	cargo clean

docker:
	docker build -t cca-test-initrd:latest .
	docker run -it -v $$PWD/..:/src -u $(shell id -u):$(shell id -g) cca-test-initrd:latest make -C cca-test-initrd
