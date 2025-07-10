# segmented-ibe-sgx
An Identity-Based-Encryption demo segmented into Setup, Encrypt, and Decrypt phases, run both inside and outside Intel SGX


## TO RUN THE PROGRAM
### Without SGX: To run entire program with gramine but outside of SGX
1. *make* '''
2. *make run-all*
   
### With SGX: To run the entire program with gramine and include SGX functionality
1. Generate SGX enclave signing key and replace value of SIGNER_KEY at the top of the MAKEFILE (only has to be done once)
   *gramine-sgx-gen-private-key -f $HOME/.config/gramine/enclave-key.pem*
3. *make SGX=1*
4. *make run-all*
