PY_SCRIPT := kga_server.py
#SAGE_DIR := INPUT YOUR LOCAL SAGE PATH
MANIFEST := nasa_implement.manifest
MANIFEST_TEMPLATE := $(MANIFEST).template
SGX_SIGNED_MANIFEST := $(MANIFEST).sgx
SIGNER_KEY := /home/kfox24/.config/gramine/enclave-key.pem
RA_TYPE ?= none
LOG_LEVEL = debug

.PHONY: all direct sgx clean run-sgx
all:
ifeq ($(SGX),1)
	@$(MAKE) sgx
else
	@$(MAKE) direct
endif

direct: $(MANIFEST)
	#Run KGA natively (no SGX)
sgx: $(SGX_SIGNED_MANIFEST)
	#Run KGA inside SGX

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

run-sgx:
	#Launches the KGA server inside SGX
	gramine-sgx nasa_implement

clean:
	rm -f $(MANIFEST) $(MANIFEST).sgx *.sig

clean-log:
	rm -f *.log