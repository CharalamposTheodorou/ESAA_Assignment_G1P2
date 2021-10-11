package x509_scanner;

import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Analyzer {

	public static int num_connections=0;
	public static int error_counter=0;
	/*
	 * 0 - TLS 1.0
	 * 1 - TLS 1.1
	 * 2 - TLS 1.2
	 * 3 - TLS 1.3
	 */
	public static double[] tls_version = {0,0,0,0};
	public static List<String> valid_domains = new ArrayList<String>();
	public static double logs_counter=0;
	public static List<String> valid_CAs = new ArrayList<String>();
	
	public static void main(String [] args) {
		//load json file with scanner outputs
		JSONParser parser = new JSONParser();
		try {
			Object obj = parser.parse(new FileReader(getPath()));
			
			
			JSONArray jsonArray = (JSONArray) obj;
			iterateJson(jsonArray);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	/**
	 * Loops through the json Array of the logs
	 * Gets all necessary information to create the analyze information
	 * @param jsonArray
	 */
	private static void iterateJson(JSONArray jsonArray) {
		for (int i=0; i<jsonArray.size() ; i++) {
			
			JSONObject entry = (JSONObject) jsonArray.get(i);
			
			String id = String.valueOf(entry.get("id"));
			String valid =String.valueOf(entry.get("valid"));
			String domain = String.valueOf(entry.get("domain"));
			String valid_CA = String.valueOf(entry.get("valid_CA"));
			String logs = String.valueOf(entry.get("logs"));
			String version = String.valueOf(entry.get("version"));
			String error = String.valueOf(entry.get("error"));
			String description = String.valueOf(entry.get("description"));
			
			//counting the logs to logs/domains average.
			logs_counter+= Double.valueOf(logs);
			
			//adding the TLS version used.
			if (version.equals("0")) {
				tls_version[0]++;
			}
			else if (version.equals("1")) {
				tls_version[1]++;
			}
			else if (version.equals("2")) {
				tls_version[2]++;
			}
			else if (version.equals("3")) {
				tls_version[3]++;
			}
			
			//Valid certificate here. 
			if (valid.equals(String.valueOf(true)))
			{
				//valid domain in cert chain. to list all domains that are validated
				valid_domains.add(domain);
				valid_CAs.add(valid_CA);
				
			}
			
		}
		
		//Percentage of valid tls versions

		double TLS_1_0 = tls_version[0]/jsonArray.size();
		double TLS_1_1 = tls_version[1]/jsonArray.size();
		double TLS_1_2 = tls_version[2]/jsonArray.size();
		double TLS_1_3 = tls_version[3]/jsonArray.size();
		System.out.println("TLS 1.0:"+TLS_1_0+" %");
		System.out.println("TLS 1.1:"+TLS_1_1+" %");
		System.out.println("TLS 1.2:"+TLS_1_2+" %");
		System.out.println("TLS 1.3:"+TLS_1_3+" %");
		
		//percentage of valid cert chains / domains
		double valid_cert_chains = (double)(valid_domains.size())/jsonArray.size();
		System.out.println("valid chains percentage:"+valid_cert_chains+" %");
		
		//percentage for logs
		double logs = logs_counter/jsonArray.size();
		System.out.println("\nlogs percentage:"+logs+" %");
		
		//number of valid CAs
		int cas_used = valid_CAs.size();
		System.out.println("\nCAs used: "+cas_used+"");
		
		//check instances of each CA
		String[] topTen = new String[10];
		int[] topTenValues = new int[10];
		for (int k=0;k<topTen.length;k++) {
			topTen[k] = "N/A";
			topTenValues[k] = 0;
		}
		int [] instances= new int[cas_used];
		for (int i=0; i<cas_used; i++) {
			instances[i] = Collections.frequency(valid_CAs,valid_CAs.get(i));
		}
		
		//loop in CAs to find Top10
		for (int i=0;i<cas_used; i++) {
			boolean found = false;
			for (int j=0;j<topTen.length; j++) {
				if (instances[i] > topTenValues[j]) { 
					//found bigger number..
					//check if name already exists..
					String new_name = valid_CAs.get(i);
					for (int k=0;k<topTen.length;k++) {
						if (topTen[k].equals(new_name)) {
							found = true;
							break;
						}
					}
					if (!found)
					{
						//no entry with this name.. add new
						topTen[j] = new_name;
						topTenValues[j]= instances[i];
						
					}
				}
			}
		}
		
		//TOP 10 CAs
		System.out.println("\nTOP CAs:");
		for (int i=0; i<topTen.length; i++) {
			
			System.out.println(topTenValues[i]+":\t\t"+topTen[i]);
		}
		
		
	}
	
	/**
	 * Returns the current working directory
	 * @return
	 */
	private static String getPath() {
		   return System.getProperty("user.dir")+"\\src\\x509_scanner\\input\\scan_output.json";
	}
}
