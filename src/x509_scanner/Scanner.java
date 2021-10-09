package x509_scanner;

/**
 * Higher class of the TLS/X.509 Scanner tool
 *
 */

public class Scanner {
	
	public static void main(String [] args) {
		//Creating the certificate Object
				//X509Certificate x = (X509Certificate);
						
				//KeyManager creation
				//KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				
		
		//Get Arguments
		
		/**
		 * [0] : input
		 * [1] : blocklist (optional)
		 * [2] : root store (optional)
		 */
		String [] file_names = new String[3];
		
		//argument counter
		int arg_counter = 0;
		System.out.println("args:"+args.toString()+" len:"+args.length);
		while (arg_counter < args.length) {
			System.out.println(" iterationg");
			if (args[arg_counter].endsWith(".txt") || args[arg_counter].endsWith(".csv") || args[arg_counter].endsWith(".pem")) {
				//file found..
				if (file_names[0] == null && args[arg_counter].endsWith(".csv"))
				{
					//input file
					file_names[0] = args[arg_counter];
					System.out.println("Adding: "+args[arg_counter]+" as input file");
				}
				else if (file_names[0]!=null && file_names[1]==null && args[arg_counter].endsWith(".txt")){
					//blocklist file 
					file_names[1] = args[arg_counter];
					System.out.println("Adding: "+args[arg_counter]+" as blocklist file");
				}
				else {
					//root store file 
					file_names[2] = args[arg_counter];
					System.out.println("Adding: "+args[arg_counter]+" as root input file");
					break;
				}
			}
			arg_counter++;
		}
		if (file_names[0].isEmpty()) {
			System.out.println("No input file is provided. Please retry again with the first input in csv or txt format.");
		}
		if (file_names[1].isEmpty()) {
			System.out.println("No block list provided.. loading default blocklist file: blocklist.txt");
			file_names[1] = "blocklist.txt";
		}
		// Checking if root file provided or load local copy
		if (file_names[2].isEmpty()) {
			System.out.println("No root store file provded.. loading default mozilla: roots.pem");
			file_names[2] = "root-store.pem";
		}
		/*
		 * for (int i=0; i<args.length; i++ ) { if (args[i].contains(".")) { //found
		 * input file. input_file_name = args[i]; break; } }
		 */
		
		int rate = 0;
		if (args.length > 0 ) 
		{
			//check if given flag for 'r' to change rate per second.
			rate = args[0].equals("-r") ? Integer.parseInt(args[1]) : 0; 
			System.out.println("Reading from :"+file_names[0]+"and making connections with a rate of "+rate+" connections per second");	
		}
		
		//Create the FileStreamInput file..
		//FileHandler inputHandler = new FileHandler(input_file_name);
		//inputHandler.readAllLines();
		ConnectionHandler handler = new ConnectionHandler(file_names,rate);
		//FileHandler blockHandler = new FileHandler(blocklist_file_name);
		//blockHandler.readAllLines();
		/*
		 * ConnectionHandler handler = new ConnectionHandler(
		 * fileHandler.getInputFile(),rate);
		 */
		
		//handler.initHandler();
	}
}
