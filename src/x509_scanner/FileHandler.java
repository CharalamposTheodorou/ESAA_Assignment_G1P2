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
	/**
	 * Returns the file lines to the FileHandler instance
	 * @return
	 */
	public List<String> readFile() {
		try {
          return Files.readAllLines(Paths.get(path),Charset.defaultCharset());
			
		}
		catch( Exception e) {
			return null;
		}
	}
	
	
	/**
	 * Returns the current working directory
	 * @param filename
	 * @return
	 */
	private String setPath(String filename) {
		   return System.getProperty("user.dir")+"\\src\\x509_scanner\\"+filename;
	}
}
