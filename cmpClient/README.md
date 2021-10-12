# cmpClient
Simple CMP Client to request or revoke a certificate using the CMP protocol, based on Bouncy Castle

## Usage
Build the project using maven: 'mvn clean install' .
Invoke the created jar and list the options:

`java -jar cmpClient-1.1.0-jar-with-dependencies.jar -h`

The cmpClient expects a CSR file to be available as a file (after the option `-i` ). Tom perform a revocation  a 
certificate file is expected (after the option `-o` ). 

Required options for the communication with the CA are:

`-u url`: the URL of the CMP endpoint of the CA
`-a alias`: the alias of the CMP processing pipeline
`-s secret`: the secret passphrase configured with the CMP processing pipeline

The CA's CMP interface is expected to be configured using password based message authentication. The password is used 
both for protecting the integrity of the request and the response. 

The CA must be configured to accept request in the RA mode, incoming requests are considered as coming from a 
trusted registration office.

The cmpClient accepts CSR, so it has no access to the private key of the requester. Therefore, the CA must be configured
to assume that 'proof of possession' of the private key of the requester is ensured. So it's up to the user to design an
appropriate process fulfilling this requirement.