# segmented-ibe-sgx
An Identity-Based-Encryption demo segmented into Setup, Encrypt, and Decrypt phases, run both inside and outside Intel SGX


## TO RUN THE PROGRAM
### Without SGX: To run entire program with gramine but outside of SGX
---Run the following in your working directory---<br>
1.<br>
   '''bash<br>
  *make*<br>
  '''<br>
2.<br>
   '''bash<br>
  *make run-all*<br>
  '''<br>
   
### With SGX: To run the entire program with gramine and include SGX functionality
---Run the following in your working directory---<br>
1.<br>
   Generate SGX enclave signing key and replace value of SIGNER_KEY at the top of the MAKEFILE (only has to be done once)<br>
   '''bash<br>
   *gramine-sgx-gen-private-key -f $HOME/.config/gramine/enclave-key.pem*<br>
   '''<br>
2. <br>
   '''bash<br>
   *make SGX=1*<br>
   '''<br>
3. <br>
   '''bash<br>
   *make run-all*<br>
   '''<br>
