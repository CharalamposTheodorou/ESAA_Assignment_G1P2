# ESAA_Assignment_G1P2

## Scanner Features:

### Input Files:
Uses 3 input files:
input.csv 	blocklist.txt 	   root-store.pem
If no input is provided then the process is stopped.
If no blocklist or root-store provided, it loads them from the input directory

Arguments:
When searching for the input files, it checks for a specific format:
input.csv 	blocklist.txt 	   root-store.pem
It accepts a rate parameter when triggered by a specific flag “-r”:
java input.csv blocklist.txt root-store.pem -r 500

Process:
Scanner.java:
Checks arguments for correct input files (if not for root-store or blocklist loads them from input directory).
Starts ConnectionHandler.java for multi-thread control.
ConnectionHandler.java:
Gets contents of the input files from FileHandler.java
Checks the validity of  the root-store certificates.
Starts a ScheduledExecutorService for reloading the contents of the blocklist.txt, in case there was an update.
Checks if provided with rate and starts new threads accordingly to have a maximum or rate threads per second. When a connection or thread is terminated it checks immediately to create a new connection (thread).
Checks before any potential new connection if ip or domain in blocklist.
At the termination of every connection(thread) receives their log back. When all connections are terminated it creates a JSON structure and stores the contents in a new JSON file.
TLSConnection.java:
Creates the TLS connections based on the ip or domain provided.
When triggered with a successful handshake, it loads the Certificate Chain. It checks first if it can validate the certificate in the chain iteratively and if there’s no success, it checks if it can validate it with the root-store certificates chains. It implements a logger Interface to log data for each connection at their termination. (CAs, validations, CT logs, error messages).
When a Certificate verifies its Issuer, it triggers a log instance and logs the connection’s data.
When an error occurs during the connection it’s handled accordingly. e.g. Exceptions triggered for example by invalid certificate format or length or wrong cipher are ignored and logged as errors in the logger.
FileHandler.java:
Checks for the location of the files and handles their InputStream.


Analysis Features:

Input Files:
Uses 1 input file:
scan_output.json

Arguments:
No arguments handled. Loads automatically the input file.
Process:
Analyzer.java:
Loads scan output in a JSON Array for a more structured and accessible format.
One JSON Object in the array is for one log. Data can be searched by ip, domain or id of the connection instance.
Sequentially goes through the logs and collects data.
Counters the instances of “TLSv1.0”,”TLSv1.1”,”TLSv1.2” and”TLSv1.3” and creates an average for each one (TLSv / domains_ips) [TLSVER]
When it finds a connection log with a verified certificate it collects the connection’s domain and the issuing CA of the certificate. Keeping track of all CAs and all domains that have successfully verified certificates in their certificate chain.
Counts the CT Logs of all connections.
Creates percentage for the verified domains ( verified_domains / all_domains). [VALID]
Creates percentage for the CT logs in the connections ( ct_logs / all_domains). [CTLOG]
Shows the number of CAs that took part in the successful verification process in the whole input file.
Iterates through the CAs and creates a Top 10 based on their usage. [ CA]
The output of all the above is shown on Terminal.
