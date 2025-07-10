# segmented-ibe-sgx
An Identity-Based-Encryption demo segmented into Setup, Encrypt, and Decrypt phases, run both inside and outside Intel SGX


## TO RUN THE PROGRAM
### Without SGX: To run entire program with gramine but outside of SGX
---Run the following in your working directory---<br>
1. Build the project<br>
   **Command:** *make*<br>
2. Run the demo<br>
  **Command:** *make run-all*<br>
   
### With SGX: To run the entire program with gramine and include SGX functionality
---Run the following in your working directory---<br>
1. Generate SGX enclave signing key (only has to be done once)<br>
   **Command:** *gramine-sgx-gen-private-key -f $HOME/.config/gramine/enclave-key.pem*<br>
   **Then update the value of SIGNER_KEY at the top of the Makefile with this path**
2. Build the project<br>
   **Command:** *make SGX=1*<br>
3. Run the demo<br>
   **Command:** *make run-all*<br>
