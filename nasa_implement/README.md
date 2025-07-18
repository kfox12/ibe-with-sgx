## Running the NASA Drone Implement
To run the NASA drone implement, 4 terminal tabs are needed
  1. KGA server <== Will run inside SGX, as it contains the master secret for all cryptography functionality 
  2. SAM server
  3. DRP manager
  4. Drone client

**Note**: 
- Because these programs utilize Elliptic-Curve Cryptography, SAGE must be installed to utilize its Python interpreter
- All of these programs use logs rather than stdout, so check *fileName*.log for updates on a specific file while it's running
- To change the alter what drone is requesting access into the airspace, change the *drone* variable at the top of drone_client.py

# Run each command in a separate terminal (first two in the same), in this order
**Note**:
- After running *make run-sgx*, check the kga_server.log for a message that the KGA is up and running before performing the rest of the commands!

Terminal tab 1: *make SGX=1*
  
  In the same terminal as previous command, *make run-sgx*  <== This command will setup SGX and begin to run the KGA server

Terminal tab 2: *sage -python drp_manager.py*

Terminal tab 3: *sage -python sam_server.py*

Terminal tab 4: *sage -python drone_client.py*

## Author
Kevin Fox

## Contributors
Hailey Butusov

Nirajan Koirala