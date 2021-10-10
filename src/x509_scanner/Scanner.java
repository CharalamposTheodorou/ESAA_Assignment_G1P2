package x509_scanner;

import java.util.concurrent.Executors;
/**
 Higher class of the TLS/X.509 Scanner tool
 *
 */

 public class Scanner { public static int countertest =0;
 
 	public static void main(String [] args) { 
 		
	 
		 /**
		  * [0] : input [1] : blocklist (optional) [2] : root store (optional)
		  */
		  String [] file_names = new String[3];
		 
		 //argument counter 
		 int arg_counter = 0;

		 while (arg_counter < args.length) { 	

		 if (args[arg_counter].endsWith(".txt") || args[arg_counter].endsWith(".csv") || args[arg_counter].endsWith(".pem")) { 
			 //file found.. 
			 if (file_names[0] ==null && args[arg_counter].endsWith(".csv")) { 
				 //input file 
				 file_names[0] = args[arg_counter];
			 } else if (file_names[0]!=null && file_names[1]==null && args[arg_counter].endsWith(".txt")){ 
				 //blocklist file
				 file_names[1] = args[arg_counter];
			 } else { 
				 //root store file 
				 file_names[2] = args[arg_counter];
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
		 } // Checking if root file provided orload local copy 
		 
		 if (file_names[2].isEmpty()) { 
			 System.out.println("No root store file provded.. loading default mozilla: roots.pem");
			 file_names[2] = "root-store.pem"; 
		 }
		 
		 
		 int rate = 0; 
		 if (args.length > 0 ) { 
			 //check if given flag for 'r' to change rate per second. 
			 rate = args[0].equals("-r") ? Integer.parseInt(args[1]) : 0;
			 System.out.println("Reading from :"+file_names[0]+"and making connections with a rate of "+rate+" connections per second"); 
		 }		 
		 
		 ConnectionHandler handler = new ConnectionHandler(file_names,rate);
	 } 
 }
		 