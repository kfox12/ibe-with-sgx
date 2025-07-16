PY_SCRIPT := basicident.py
SAGE_DIR := /data/sage
MANIFEST := basicident.manifest
MANIFEST_TEMPLATE := $(MANIFEST).template
SGX_SIGNED_MANIFEST := $(MANIFEST).sgx
#Used for remote attestation
#SGX_TOKEN := $(PY_SCRIPT).token
#Must generate before using the enclave
SIGNER_KEY := /home/kfox24/.config/gramine/enclave-key.pem
RA_TYPE ?= none

.PHONY: all direct sgx clean run-setup run-encrypt run-decrypt run-all
all:
ifeq ($(SGX),1)
	@$(MAKE) sgx
else
	@$(MAKE) direct
endif

direct: $(MANIFEST)
	#Generates manifest for direct
sgx: $(SGX_SIGNED_MANIFEST)
	#Generates manifest and signiture file

$(MANIFEST): $(MANIFEST_TEMPLATE)
	gramine-manifest -Dpy_script=$(PY_SCRIPT) \
		-Dsage_dir=$(SAGE_DIR) \
		-Dra_type=$(RA_TYPE) \
		$< $@

$(SGX_SIGNED_MANIFEST): $(MANIFEST)
	gramine-sgx-sign \
	--key $(SIGNER_KEY) \
	--manifest $< \
	--output $@

run-setup:
	gramine-sgx basicident setup

run-encrypt:
	/data/sage/venv/bin/python3 basicident.py encrypt

run-decrypt:
	/data/sage/venv/bin/python3 basicident.py decrypt

run-all: run-setup run-encrypt run-decrypt

clean:
	rm -f $(MANIFEST) $(MANIFEST).sgx *.sig