package x509_scanner;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import org.apache.commons.net.util.*;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.apache.commons.validator.*;
import org.apache.commons.validator.routines.InetAddressValidator;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;


public class ConnectionHandler {
	
	

	/**
	 * Relevant information for logging during an event at the TLS connection
	 *
	 */
	public class TLSLog {
		int id;
		String domain;
		String ip;
		int logs_counter;
		boolean validated;
		String valid_CA;
		String error;
		String description;
		int version;
		
		TLSLog(int id, String domain, String ip, int logs_counter, boolean validated, String valid_CA, String error, String description,int version) {
			this.id = id;
			this.domain = domain;
			this.ip = ip;
			this.logs_counter = logs_counter;
			this.validated = validated;
			this.valid_CA = valid_CA;
			this.error= error;
			this.version = version;
			this.description = description;
		}
	}
	
	protected class ConnectionLogger implements TLSConnection.ConnectionInterface {
		private int id;
		private String status;
		private String ip;
		private String domain;
		
		private List<TLSLog> logs = new ArrayList<TLSLog>();
				
		protected void setId(int id) {
			this.id = id;
		}

		protected void setStatus(String status) {
			this.status = status;
		}

		protected void setIp(String ip) {
			this.ip = ip;
		}

		protected void setDomain(String domain) {
			this.domain = domain;
		}

				
		@Override
		public void onSendLogs(int logs_counter, boolean validated, String valid_CA, String error, String description,int version) {
			
		
			
			//adding new entry to log.
			TLSLog log = new TLSLog(this.id,this.domain,this.ip,logs_counter,validated,valid_CA,error,description,version);
			loggers.add(log);
			
			TOTAL_CONNECTIONS_TERMINATED++;
			if (currentEntry < input_list.size()) {
				// Connection Terminated and available new connections
				createNewConnection();
			}
			else {
				//initiated maximum connections. check if last termination to export logs
				if (TOTAL_CONNECTIONS_TERMINATED == TOTAL_CONNECTIONS_INITIATED)
				{
					System.out.println("End of Scaning here.. FInal thread and connection terminated");
					EndOFScan();
				}
			}
		}
	}

	private static class InputListHandler {
		private static FileHandler inputListHandler;

		public InputListHandler() {
			this.readFile();
		}

		private void readFile() {
			inputListHandler = new FileHandler(INPUT_FILE_NAME);
			InetAddressValidator ipValidator = new InetAddressValidator();
			List<String> inputList = inputListHandler.readFile();

			if (inputList == null) {
				System.out.println("Input file not obtained correctly. Proceeding without");
			} else if (inputList.isEmpty()) {
				System.out.println("Input file is empty. Proceeding without.");
			} else {

				for (String inputLine : inputList) {
					String[] split = inputLine.split(",");
					// check if valid ip or ignore..
					if (ipValidator.isValid(split[0])) {
						// ip found in position 0 adding info
						// domain at position 0 and ip at 1
						String[] new_entry = new String[2];
						new_entry[0] = split[1];
						new_entry[1] = split[0];
						input_list.add(new_entry);
					} else if (ipValidator.isValid(split[1])) {

						// ip found in position1 adding info
						// domain at position 0 and ip at 1
						input_list.add(split);
					} 
					/*
					 * else { System.out.println("Not valid ip for domain:" + split[0] + " -> " +
					 * split[1]); }
					 */
				}
			}
		}
	}

	private static class RootListHandler {
		private static FileHandler rootListHandler;

		public RootListHandler() {
			// Read file() and get lines;
			// Create two initial String[] ips and domains
			// Go through ips to get the range of them.

			this.readFile();
		}

		private void readFile() {
			rootListHandler = new FileHandler(ROOTSTORE_FILE_NAME);

			List<String> rootListLines = rootListHandler.readFile();
			String allPems = String.join("\n", rootListLines);
			if (rootListLines == null) {
				System.out.println("Root store not obtained correctly. Proceeding without");
			} else if (rootListLines.isEmpty()) {
				System.out.println("Root store is empty. Proceeding without.");
			} else {
				
				//removing special characters from pem file
				if (allPems.contains("\t")) {
					allPems = allPems.split("\t").toString();
				}
				if (allPems.contains(",")) {
					allPems = allPems.split(",").toString();
				}
				String[] pems_splited = allPems.split("-----BEGIN CERTIFICATE-----");

				for (String pem : pems_splited) {
					rootstore_list.add("-----BEGIN CERTIFICATE-----" + pem);
				}
				//removes extra record of "-------BEGIN CERTIFICATE-----"
				rootstore_list.remove(0);
			}

		}
	}


	private static class BlockListHandler {
		private static FileHandler blockList;
		
		public BlockListHandler() {
			// Read file() and get lines;
			// Create two initial String[] ips and domains
			// Go through ips to get the range of them.

			this.readFile();
			this.bonBlock();
		}

		private void readFile() {
			blockList = new FileHandler(BLOCKLIST_FILE_NAME);
			InetAddressValidator ipValidator = new InetAddressValidator();
			List<String> blockListLines = blockList.readFile();
			List<String> blocklist_ips_temp = new ArrayList<String>();
			List<String> blocklist_domains_temp = new ArrayList<String>();
			
			if (blockListLines == null) {
				System.out.println("Block list not obtained correctly. Proceeding without");
			} else if (blockListLines.isEmpty()) {
				System.out.println("Block list is empty. Proceeding without.");
			} else {
				// spliting domains from ips.
				
				for (int i = 0; i < blockListLines.size(); i++) {
					// check if ip or domain by checking for letters
					String line = blockListLines.get(i);
					//checks if an ip or domain
					if (line.matches(".*[a-zA-Z]+.*")) {
						// if true then entry contains letter -> domain value
						blocklist_domains_temp.add(line);
					} else {
						// ip found..
						// process ip to set ranges.
						// split between '/': ip and subnet mask
						// check first if valid IP.
						String ip = line.split("/")[0];
						if (ipValidator.isValid(ip)) {
							// valid ip adding to blocklist
							blocklist_ips_temp.add(line);
						}
						// else ignore. do nothing..
					}
				}
				//refreshing the blocklists (BONBLOCK)
				blocklist_ips.clear();
				blocklist_ips.addAll(blocklist_ips_temp);
				blocklist_domains.clear();
				blocklist_domains.addAll(blocklist_domains_temp);
			}
			
		}
		
		/**
		 * Scheduler that sleeps for 5 seconds and updates the Block list file
		 * (BON BLOCK)
		 */
		private void bonBlock() {
			ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();
			exec.scheduleAtFixedRate(new Runnable() {
			  @Override
			  public void run() {
				  readFile();
			  }
			}, 0, 5, TimeUnit.SECONDS);
		}
	}
	
	private static int MAX_CONNECTIONS = 0;
	public static String INPUT_FILE_NAME;
	public static String BLOCKLIST_FILE_NAME;
	public static String ROOTSTORE_FILE_NAME;
	
	private static int TOTAL_CONNECTIONS_TERMINATED = 0;
	private static int TOTAL_CONNECTIONS_INITIATED = 0;
	public static List<X509Certificate> trustedCertificates = new ArrayList<X509Certificate>();
	
	private static List<String[]> input_list = new ArrayList<String[]>();
	private static List<String> blocklist_domains = new ArrayList<String>();
	private static List<String> blocklist_ips = new ArrayList<String>();
	public static List<String> rootstore_list = new ArrayList<String>();

	private static int currentEntry = 1;
	private BlockListHandler blocklist_handler;
	
	private List<TLSLog> loggers = new ArrayList<TLSLog>();
	
	public ConnectionHandler(String[] file_names, int rate) {
		/**
		 * [0] : input [1] : blocklist (optional) [2] : root store (optional)
		 */
		this.INPUT_FILE_NAME = file_names[0];
		this.BLOCKLIST_FILE_NAME = file_names[1];
		this.ROOTSTORE_FILE_NAME = file_names[2];
		this.MAX_CONNECTIONS = rate;
		
		// setting up the file readers.
		BlockListHandler blockListHandler = new BlockListHandler();
		RootListHandler rootListHandler = new RootListHandler();
		InputListHandler inputListHandler = new InputListHandler();
		
		initHandler();
	}
	
	/**
	 * Initial check on the root store pem file
	 * Checks if all are valid.
	 * @throws Exception
	 */
	private void storeAndValidateCAs() throws Exception {
		int count_validated = 0;
		try {
			
			//create default keystore
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null,null);

			for (int i=0; i<rootstore_list.size(); i++) {
				//InputStream from .pem file
				InputStream in = new ByteArrayInputStream(rootstore_list.get(i).getBytes());
				
				//Creating the X.509 Certificate
				CertificateFactory cf = CertificateFactory.getInstance("X.509");   
				X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(in);
				
				//setting the certificate to the keystore
				trustStore.setCertificateEntry(Integer.toString(1), caCertificate);
				trustedCertificates.add(caCertificate);
				
				try {
					//checking if valide Certificate
					count_validated++;
					caCertificate.checkValidity();
					
				} 
				catch(Exception e){
					//not valid.
					count_validated--;
				}  
			}
		} catch( Exception e) {
			count_validated--;
		}
		
	}
	
	/**
	 * Hanles the initial process of the scanner operation
	 */
	public void initHandler() {
		//Initial check to log whether all Certificates are Validated.
		try {
			storeAndValidateCAs();
		}
		catch(Exception e) {
		}
		
		// check if a given rate of connections is given.
		if (MAX_CONNECTIONS != 0) {
			// Fixed rate of Connections per second is set
			while (currentEntry <= input_list.size()) {
				/*
				 * greedy algorithm make MAX_CONNECTIONS at beginning once a connection-thread
				 * is terminated makes a new connection
				 */
				while (currentEntry <= MAX_CONNECTIONS) {
					// Creates a new TLS Connection
					createNewConnection();
				}
			}
		} else {
			// no restriction. run all connections simultaneously
			for (currentEntry = 0; currentEntry < input_list.size(); currentEntry++) {
				createNewConnection();
			}
		}
		
	}

	/**
	 * Creates a new Thread for a new TLSConnection Class that handles the next TLS
	 * connection request Assigns a logger for that TLSConnection instance to report
	 * back to the ConnectionHandler.
	 */
	private void createNewConnection() {
		if (currentEntry < input_list.size()) {
			// add next entry..
			boolean isValid = false;
			boolean blocked_found = false;
			//checks while the next entry to TLS connect is valid and not in block list
			while (!isValid && currentEntry < input_list.size()) {
				String blocker = "";
				isValid = false;
				blocked_found = false;
				//goes through the domains
				for (String domain : blocklist_domains) {
					if (domain.equalsIgnoreCase(input_list.get(currentEntry)[0])) {
						// found blocked domain.. skipping entry..
						blocked_found = true;
						blocker = domain;
						break;
					}
				}
				if (!blocked_found) {
					// checking for ips now
					for (String blockedIp : blocklist_ips) {
						// getting the info of the next blocked subnet ip.
						SubnetInfo ip = (new SubnetUtils(blockedIp)).getInfo();
						// checking if input ip is in range of blocked subnet.
						if (ip.isInRange(input_list.get(currentEntry)[1])) {
							// found blocked ip in range
							blocked_found = true;
							blocker = blockedIp;
							break;
						}
					}
				}
				if (blocked_found) {
					// move to next entry until valid entry..

					currentEntry++;
				} else {
					// not blocked by ip or domain lists.
					isValid = true;
				}

			}

			if (currentEntry < input_list.size()) {
				// proceed normal
				String[] new_entry = input_list.get(currentEntry);
				//domain at [0]
				//ip at [1]
				
				 // Create new ConnectionLogger 
				ConnectionLogger connLogger = new ConnectionLogger();
				connLogger.setId(currentEntry);
				connLogger.setDomain(new_entry[0]);
				connLogger.setIp(new_entry[1]);
						
				// New Thread for the TLSConnection Class 
				TOTAL_CONNECTIONS_INITIATED++;
				Thread t1 = new Thread( new TLSConnection(currentEntry, new_entry[0], new_entry[1], connLogger)); 
				// connection counter 
				currentEntry++; 
				// thread start 
				t1.start();
				
			}
			
			 
		} else {
			return;
		}
	}
	
	/**
	 * Triggered when scanning is done and creates the JSON output file from the logs
	 */
	private void EndOFScan() {
		JSONArray arrayLogs = new JSONArray();
		
		for (int i=0; i< loggers.size(); i++) {
			TLSLog log = loggers.get(i);
			
			JSONObject json = new JSONObject();
			
			json.put("id", log.id);
			json.put("domain",log.domain);
			json.put("logs",log.logs_counter);
			json.put("valid",log.validated);
			json.put("valid_CA",log.valid_CA);
			json.put("version",log.version);
			json.put("error",log.error);
			json.put("description",log.description);
			json.put("ip",log.ip);
			arrayLogs.add(json);
		}
		try {
			FileWriter file = new FileWriter(System.getProperty("user.dir")+"\\src\\x509_scanner\\input\\scan_output.json");
			file.write(arrayLogs.toJSONString());
			file.close();
		} catch (Exception e) {
			System.out.println(e.getMessage()+" at storing the output of the scan.");
		} finally {
			System.out.println("Scan Output stored at scan_output.json");
			System.exit(1);
		}
	}
}
