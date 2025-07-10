# segmented-ibe-sgx
An Identity-Based-Encryption demo segmented into Setup, Encrypt, and Decrypt phases, run both inside and outside Intel SGX


## TO RUN THE PROGRAM
### Without SGX: To run entire program with gramine but outside of SGX
---Run the following in your working directory---  return
1.
   '''bash
  *make*
  '''
2.
   '''bash
  *make run-all*
  '''
   
### With SGX: To run the entire program with gramine and include SGX functionality
---Run the following in your working directory---
1.
   Generate SGX enclave signing key and replace value of SIGNER_KEY at the top of the MAKEFILE (only has to be done once)
   '''bash
   *gramine-sgx-gen-private-key -f $HOME/.config/gramine/enclave-key.pem*
   '''
2. 
   '''bash
   *make SGX=1*
   '''
3. 
   '''bash
   *make run-all*
   '''
