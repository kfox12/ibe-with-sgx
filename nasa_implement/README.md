**Running the NASA Drone Implement**
To run the NASA drone implement, 3 terminal tabs are needed
  1. KGA server
  2. SAM server
  3. Drone client

**Note**: 
- Because these programs utilize Elliptic-Curve Cryptography, SAGE must be installed to utilize its Python interpreter
- To change the alter what drone is requesting access into the airspace, change the *drone* variable at the top of drone_client.py

**Run each command in a separate terminal, in this order**
*sage -python kga_server.py*
*sage -python sam_server.py*
*sage -python drone_client.py*