package x509_scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;

class FileHandler {
	String filename;
	String path; 
	ArrayList<String[]> entries = new ArrayList<String[]>();
	
	FileHandler(String filename) {
		this.filename = filename;
		this.path = setPath(filename);
	}
	//TODO: fix exceptions and return messages..
	//TODO: handler to check if block file changes.. trigger next threads to change the blocklist reference by updating the ArrayList of the Ips or domains.
	
	/**
	 * Returns the file lines to the FileHandler istance
	 * @return
	 */
	public List<String> readFile() {
		try {
			
          return Files.readAllLines(Paths.get(path),Charset.defaultCharset());
			
		}
		catch(FileNotFoundException e) {
			System.out.println("FileNotFoundException: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		catch(IOException e) {
			System.out.println("IOException: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		catch( Exception e) {
			System.out.println("Exception: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		return null;
	}
	
	public String readAllLines() {
		
		try {
							
	//		URI uri = this.getClass().getResource(path).toURI();
          List<String> lines = Files.readAllLines(Paths.get(path),Charset.defaultCharset());
            System.out.println("Line 2:"+lines.get(2));
            System.out.println("Test:\n"+lines.toString());
			
//		}catch(FileNotFoundException e) {
//			System.out.println("FileNotFoundException: " +e.getMessage());
//			System.out.println("trace:"+e.getStackTrace());
//		}
//		catch(IOException e) {
//			System.out.println("IOException: " +e.getMessage());
//			System.out.println("trace:"+e.getStackTrace());
		}
		catch( Exception e) {
			System.out.println("Exception: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		
		return "";
	}
	
	/**
	 * Creates an input stream for the file and returns its contents..
	 * @param filename
	 */
	private void readInputFile() {
		
		try {
			File file = new File(path);
			byte[] bytesArray = new byte[(int) file.length()];
			FileInputStream fstream = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(fstream));
			
			//Read file line by line and create the configs
			String line;
			while((line = br.readLine()) != null ) {
				String [] tmp = line.split("\t");
				entries.add(tmp);
				for (int i=0;i<tmp.length; i++) {
					System.out.print(tmp[i]+"\t");
				}
				System.out.println();
			}
			fstream.close();
			br.close();
			
			
		}
		catch(FileNotFoundException e) {
			System.out.println("FileNotFoundException: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		catch(IOException e) {
			System.out.println("IOException: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
		catch( Exception e) {
			System.out.println("Exception: " +e.getMessage());
			System.out.println("trace:"+e.getStackTrace());
		}
	}
	
	public ArrayList<String[]> getInputFile() {

		this.readInputFile();
		
		return entries;
	}
	
	/**
	 * Returns the current working directory
	 * @param filename
	 * @return
	 */
	private String setPath(String filename) {
		   return System.getProperty("user.dir")+"\\src\\x509_scanner\\input\\"+filename;
	}
}
