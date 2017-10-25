.PHONY: all
all: linux android

.PHONY: linux
linux:
	cargo build --target=x86_64-unknown-linux-gnu $(flags)

.PHONY: android
android:
	PATH=$$HOME/Downloads/android-21-toolchain/bin:$$PATH \
	cargo build --target=arm-linux-androideabi $(flags)

.PHONY: clean
clean:
	rm -rf target
