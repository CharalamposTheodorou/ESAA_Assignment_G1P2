package x509_scanner;

import java.util.ArrayList;
import org.apache.commons.net.util.*;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.apache.commons.validator.*;
import org.apache.commons.validator.routines.InetAddressValidator;

import java.util.List;

public class ConnectionHandler {
	// TODO: one logger for each TLS connection? To have an entry for each different
	// connection.

	protected class ConnectionLogger implements TLSConnection.ConnectionInterface {
		private int id;
		private String status;
		private String ip;
		private String domain;
		
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
		public void onConnectionEndSuccessfully(int id, String message, long timestamp) {
			// TODO Auto-generated method stub
			System.out.println("onConnectionEndSuccessfull/n message:" + message + "/n@" + timestamp);
			// TODO: check here if available threads and connections with rate..
			System.out.println("Thread is terminated.. One space for new connection is available...");
			if (currentEntry <= tlsList.size()) {
				// Connection Terminated and available new connections
				createNewConnection();
			}

		}

		@Override
		public void onConnectionEndFailure(int id, String message, long timestamp, String error) {
			// TODO Auto-generated method stub

			System.out.println("onConnectionEndFailure");
		}

		@Override
		public void onConnectionStartSuccessfully(int id, String message, long timestamp) {
			// TODO Auto-generated method stub

			System.out.println("onConnectionStartuccessfull");
		}

		@Override
		public void onConnectionStartFailure(int id, String message, long timestamp, String error) {
			// TODO Auto-generated method stub

			System.out.println("onConnectionStartFailure");
		}

		@Override
		public void onMessageLog(int id, String message, long timestamp) {
			// TODO Auto-generated method stub

			System.out.println("onMessageLog");
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
			System.out.println("FIrst: " + inputList.get(0));

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
				String[] pems_splited = allPems.split("-----BEGIN CERTIFICATE-----");

				for (String pem : pems_splited) {
					rootstore_list.add("-----BEGIN CERTIFICATE-----" + pem);
				}
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
		}

		private void readFile() {
			blockList = new FileHandler(BLOCKLIST_FILE_NAME);
			InetAddressValidator ipValidator = new InetAddressValidator();
			List<String> blockListLines = blockList.readFile();
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
					System.out.println("Checking for:" + line);
					if (line.matches(".*[a-zA-Z]+.*")) {
						System.out.println("domain ");
						// if true then entry contains letter -> domain value
						blocklist_domains.add(line);
					} else {
						System.out.println("ip ");
						// ip found..
						// process ip to set ranges.
						// split between '/': ip and subnet mask
						// check first if valid IP.
						String ip = line.split("/")[0];
						if (ipValidator.isValid(ip)) {
							// valid ip adding to blocklist
							blocklist_ips.add(line);
						}
						// else ignore. do nothing..
					}
				}
			}

		}

		// TODO: replace file every 2 seconds..

	}

	private static int MAX_CONNECTIONS = 0;
	public static String INPUT_FILE_NAME;
	public static String BLOCKLIST_FILE_NAME;
	public static String ROOTSTORE_FILE_NAME;

	private static ArrayList<String[]> tlsList = new ArrayList<String[]>();

	private static List<String[]> input_list = new ArrayList<String[]>();
	private static List<String> blocklist_domains = new ArrayList<String>();
	private static List<String> blocklist_ips = new ArrayList<String>();
	private static List<String> rootstore_list = new ArrayList<String>();

	private static int currentEntry = 1;
	private BlockListHandler blocklist_handler;

	// TODO: for root store input . split wih "-----BEGIN CERTIFICATE-----" and
	// append it to each entry..

	// TODO: if blcoklist contains IP subnet then need to find the range of that
	// subnet to block..
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

	public ConnectionHandler(ArrayList<String[]> tlsList) {
		ConnectionHandler.tlsList = tlsList;
	}

	ConnectionHandler(ArrayList<String[]> tlsList, int maxConnections) {
		ConnectionHandler.tlsList = tlsList;
		ConnectionHandler.MAX_CONNECTIONS = maxConnections;
		// TODO: create to all constructors the logger for the whole process here..
	}

	public void initHandler() {
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
					System.out.println(
							input_list.get(currentEntry)[0] + "," + input_list.get(currentEntry)[1] + "is not blocked");
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
				//TODO: here proceed to build the TLS connection structure..
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

}
