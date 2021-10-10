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
	// TODO: one logger for each TLS connection? To have an entry for each different
	// connection.
	
	/**
	 * Relevant information for logging during the whole scanning process
	 * For CAs certificates validation
	 * Errors during connection
	 * Other events
	 *
	 */
	protected class ScannerEntry {
		long timestamp;
		String description;
		String error;
		String ip;
		String domain;
		
		ScannerEntry(long timestamp, String description) {
			this.timestamp = timestamp;
			this.description = description;
		}
		
		ScannerEntry(long timestamp, String description, String error) {
			this.timestamp = timestamp;
			this.description = description;
			this.error = error;
		}
		
		ScannerEntry(long timestamp, String description, String ip, String domain) {
			this.timestamp = timestamp;
			this.description = description;
			this.error = error;
			this.ip = ip;
			this.domain = domain;
		}
		
		ScannerEntry(long timestamp, String description, String error, String ip, String domain) {
			this.timestamp = timestamp;
			this.description = description;
			this.error = error;
			this.ip = ip;
			this.domain = domain;
		}
	}
	

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
		

//		protected class Entry {
//			long timestamp;
//			int id;
//			String tag;
//			String value;
//			String ip;
//			String domain;
//			String description;
//			String error;
//			
//			Entry(long timestamp, int id, String ip, String domain, String description, String tag, String value) {
//				this.timestamp = timestamp;
//				this.id = id;
//				this.description = description;
//				this.ip = ip;
//				this.domain = domain;
//				this.tag = tag;
//				this.value = value;
//			}
//			
//			Entry(long timestamp, int id, String ip, String domain, String description) {
//				this.timestamp = timestamp;
//				this.id = id;
//				this.description = description;
//				this.ip = ip;
//				this.domain = domain;
//				this.error = error;
//			}
//			
//			Entry(long timestamp, int id, String ip, String domain, String description, String error) {
//				this.timestamp = timestamp;
//				this.id = id;
//				this.description = description;
//				this.ip = ip;
//				this.domain = domain;
//				this.error = error;
//			}
//			
//			Entry(long timestamp, int id, String ip, String domain, String description, String error, String tag, String value) {
//				this.timestamp = timestamp;
//				this.id = id;
//				this.description = description;
//				this.ip = ip;
//				this.domain = domain;
//				this.error = error;
//				this.tag = tag;
//				this.value = value;
//			}
//		}
		
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
//TODO: handle the messages and the entries how are finalized for next input file..
		
//		@Override
//		public void onConnectionEndSuccessfully(int id, String message, long timestamp) {
//			// TODO Auto-generated method stub
//			System.out.println("onConnectionEndSuccessfull/n message:" + message + "/n@" + timestamp);
//			
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message));
//			// TODO: check here if available threads and connections with rate..
//			
//
//		}
//
//		@Override
//		public void onConnectionEndFailure(int id, String message, long timestamp, String error) {
//			// TODO Auto-generated method stub
//
//			System.out.println("onConnectionEndFailure");
//
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message,error));
//		}
//		
//		@Override
//		public void onThreadStart(int id, String message, long timestamp) {
//			// TODO Auto-generated method stub
//
//			System.out.println("onThreadStart:"+message +" @"+ timestamp);
//
//			scanner_entries.add(new ScannerEntry(timestamp,message,this.ip,this.domain));
//		}
		
		@Override
		public void onSendLogs(int logs_counter, boolean validated, String valid_CA, String error, String description,int version) {
			
			//System.out.println("ID:"+this.id+", domain:"+this.domain+", logs:"+logs_counter+", valid:"+validated+", CA:"+valid_CA+", error:"+error+", description:"+ description);
			
			TLSLog log = new TLSLog(this.id,this.domain,this.ip,logs_counter,validated,valid_CA,error,description,version);
			
			loggers.add(log);
			System.out.println("Thread is terminated.. One space for new connection is available...");
			System.out.println("Current Entry:"+currentEntry);
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
					//TODO: handle json creation here..
					
					EndOFScan();
				}
				else
				{
					System.out.println("INitiated:"+TOTAL_CONNECTIONS_INITIATED+", terminated:"+TOTAL_CONNECTIONS_TERMINATED);
				}
			}
		}
		
//		@Override
//		public void onThreadEnd(int id, String message, long timestamp) {
//			// TODO Auto-generated method stub
//			
//			System.out.println("onThreadEnd:"+message +" @"+ timestamp);
//
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message));
//			//dump logger entries to Scanner Level
//			loggers.addAll(entries);
//			System.out.println("Thread is terminated.. One space for new connection is available...");
//			System.out.println("Current Entry:"+currentEntry);
//			TOTAL_CONNECTIONS_TERMINATED++;
//			if (currentEntry < input_list.size()) {
//				// Connection Terminated and available new connections
//				createNewConnection();
//			}
//			else {
//				//initiated maximum connections. check if last termination to export logs
//				if (TOTAL_CONNECTIONS_TERMINATED == TOTAL_CONNECTIONS_INITIATED)
//				{
//					System.out.println("End of Scaning here.. FInal thread and connection terminated");
//					//TODO: handle json creation here..
//					
//					EndOFScan();
//				}
//				else
//				{
//					System.out.println("INitiated:"+TOTAL_CONNECTIONS_INITIATED+", terminated:"+TOTAL_CONNECTIONS_TERMINATED);
//				}
//			}
//		}
//		
//		@Override
//		public void onConnectionStartSuccessfully(int id, String message, long timestamp) {
//			// TODO Auto-generated method stub
//
//			System.out.println("onConnectionStartuccessfull:"+message);
//
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message));
//		}
//
//		@Override
//		public void onConnectionStartFailure(int id, String message, long timestamp, String error) {
//			// TODO Auto-generated method stub
//
//			System.out.println("onConnectionStartFailure");
//
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message,error));
//		}
//
//		@Override
//		public void onMessageLog(int id, String message, long timestamp, String tag, String value) {
//			System.out.println("onMessageLog");
//
//			entries.add(new Entry(timestamp,this.id,this.ip,this.domain,message));
//		}

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
					} else {
						System.out.println("Not valid ip for domain:" + split[0] + " -> " + split[1]);
					}
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
				
				if (allPems.contains("\t")) {
					System.out.println("found tab..");
					allPems = allPems.split("\t").toString();
				}
				if (allPems.contains(",")) {
					System.out.println("found comma..");
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

	// TODO: all files are obtained..
	// TODO: check at before running the thread if next input entry is inside the
	// blocklist..

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
				System.out.println("Moving normally..");
				// spliting domains from ips.

				for (int i = 0; i < blockListLines.size(); i++) {
					// check if ip or domain by checking for letters
					String line = blockListLines.get(i);
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
				blocklist_ips.clear();
				blocklist_ips.addAll(blocklist_ips_temp);
				blocklist_domains.clear();
				blocklist_domains.addAll(blocklist_domains_temp);
			}
			
		}
		
		/**
		 * Scheduler that sleeps for 5 seconds and updates the Block list file
		 */
		private void bonBlock() {
			ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();
			//TODO: remove comment below for bonBlock
//			exec.scheduleAtFixedRate(new Runnable() {
//			  @Override
//			  public void run() {
//				  System.out.println("reading blcok list");
//				  readFile();
//				  System.out.println("Size of block list ips:"+blocklist_ips.size()+"\t size of domains:"+blocklist_domains.size());
//			  }
//			}, 0, 5, TimeUnit.SECONDS);
		}
		// TODO: replace file every 2 seconds..

	}
	//TODO: enable bonblock code at end
	
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
	private List<ScannerEntry> scanner_entries = new ArrayList<ScannerEntry>();
	
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
		
		//TODO: below.
		initHandler();
	}
	
	private void storeAndValidateCAs() throws Exception {
		int count_validated = 0;
		try {
			
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null,null);

			for (int i=0; i<rootstore_list.size(); i++) {
				//System.out.print("PEM:\n"+pems.get(i));
				InputStream in = new ByteArrayInputStream(rootstore_list.get(i).getBytes());
				CertificateFactory cf = CertificateFactory.getInstance("X.509");   
				//FileInputStream finStream = new FileInputStream(System.getProperty("user.dir")+"\\src\\x509_scanner\\input\\pem1.pem"); 

				X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(in);

				trustStore.setCertificateEntry(Integer.toString(1), caCertificate);
				trustedCertificates.add(caCertificate);

				//System.out.println(caCertificate.toString());
				try {
					count_validated++;

					
					caCertificate.checkValidity();
					
				} 
				catch(Exception e){
		            //System.out.println(caCertificate.toString());
		            System.out.println("Certificate not trusted1. it's expired");
		            System.out.println(e.getLocalizedMessage());
		            System.out.println(e.getMessage());
					count_validated--;
					//throw new CertificateException("Certificate not trusted. It has expired",e);
		            
				}  
			}
		} catch( Exception e) {
			System.out.println("here?1");
			System.out.println(e.getLocalizedMessage());
			System.out.println(e.getMessage());
			count_validated--;
		}
		//TODO: add to report or analyzer
		//TODO: remove scanner_entries?
		System.out.println("Total Certificates:"+rootstore_list.size()+". Valid:"+count_validated);
		scanner_entries.add(new ScannerEntry(System.currentTimeMillis(),"Certificates from ROOT STORE: "+rootstore_list.size()+". Valid:"+count_validated+". Expired:"+(rootstore_list.size()-count_validated)));
		
	}
	
	public void initHandler() {
		//Initial check to log whether all Certificates are Validated.
		try {
			storeAndValidateCAs();
		}
		catch(Exception e) {
			System.out.println("here?2");
			System.out.println(e.getLocalizedMessage());
			System.out.println(e.getMessage());
		}
		
		// check if a given rate of connections is given.
		if (MAX_CONNECTIONS != 0) {
			// Fixed rate of Connections per second is set
			while (currentEntry <= input_list.size()) {
				/*
				 * greedy algorithm make MAX_CONNECTIONS at beginning once a connection-thread
				 * is terminated makes a new connection
				 */
				//TODO: change rate value below
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
			while (!isValid && currentEntry < input_list.size()) {
				String blocker = "";
				isValid = false;
				blocked_found = false;
				for (String domain : blocklist_domains) {
					// System.out.println("searching for:"+ input_list.get(currentEntry)[0]+" with"+
					// domain);
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
					System.out.println(input_list.get(currentEntry)[0] + "," + input_list.get(currentEntry)[1]
							+ "is blocked with:" + blocker);

					currentEntry++;
				} else {
					// not blocked by ip or domain lists.
//					System.out.println(
//							input_list.get(currentEntry)[0] + "," + input_list.get(currentEntry)[1] + "is not blocked");
					isValid = true;
				}

			}//TODO: new instance of block list for each connection to ensure that the update doesn't affect the running threads

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
				//TODO: here proceed to build the TLS connection structure..
				TOTAL_CONNECTIONS_INITIATED++;
				Thread t1 = new Thread( new TLSConnection(currentEntry, new_entry[0], new_entry[1], connLogger)); 
				// connection counter 
				currentEntry++; 
				// thread start 
				t1.start();
				
			} else {
				// end of entries..
				// end process and produce results..
			}
			
			 
		} else {
			return;
		}
	}
	//TODO: remove all system.out
	//TODO: check tags for error -> message
	//TODO: tags for thread start and end -> scanner entry.. with ip, domain attached..

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
			System.out.println(e.getMessage()+" add storing the output of the scan.");
		} finally {
			System.out.println(arrayLogs);
			System.exit(1);
		}
	}
}
