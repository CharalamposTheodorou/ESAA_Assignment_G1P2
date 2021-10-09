package x509_scanner;

import java.util.concurrent.TimeUnit;

import x509_scanner.ConnectionHandler.ConnectionLogger;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;

public class TLSConnection implements Runnable {
	
	/**
	 * Interface to handle the messages/responses and Errors of the TLS connection
	 * Returns log information to the ConnectionHandler class
	 * Returns all responses and messages received
	 * @author USER
	 *
	 */
	public interface ConnectionInterface {
		/*
		 * Returns on the implementing class the data from the successful connection End
		 */
		void onConnectionEndSuccessfully(int id, String message, long timestamp);
		

		/*
		 * Returns on the implementing class the data from the failed connection End
		 */
		void onConnectionEndFailure(int id, String message, long timestamp, String error);
		

		/*
		 * Returns on the implementing class the data from the successful connection Start
		 */
		void onConnectionStartSuccessfully(int id, String message, long timestamp);
		

		/*
		 * Returns on the implementing class the data from the failed connection Start
		 */
		void onConnectionStartFailure(int id, String message, long timestamp, String error);
		

		/*
		 * Returns on the implementing class the data from the message
		 */
		void onMessageLog(int id, String message, long timestamp);
		
	}
	
	private int id;
	private long timestampStart;
	private long timestampEnd;
	private String version;
	private String domain;
	private String IP;
	
	private ConnectionInterface logger;
	
	public TLSConnection(int id, String ip, String domain, /* String version, */ ConnectionLogger logger) {
		this.id = id;
		this.IP = ip;
		//this.version = version;
		this.domain = domain;
		this.logger = logger;		
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		//Make the connection to the next path
		try {
			logger.onConnectionStartSuccessfully(id,"new Thread: ID: \"+id+\", started on:" , System.currentTimeMillis());
			SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket)factory.createSocket("www.verisign.com",443);
			
			//Tunneling? tunnel socket and tunnel handshake first
			
			//Create socket listener for the handshake
			socket.addHandshakeCompletedListener(
				new HandshakeCompletedListener() {
					
					@Override
					public void handshakeCompleted(HandshakeCompletedEvent event) {
						// TODO Auto-generated method stub
						System.out.println("handshake completed?");
					}
				}
			);
			
			//start the handshake
			socket.startHandshake();
			
			PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                    new OutputStreamWriter(
                    socket.getOutputStream())));

			out.println("GET / HTTP/1.0");
			out.println();
			out.flush();

			/*
             * Make sure there were no surprises
             */
            if (out.checkError())
                System.out.println(
                    "SSLSocketClient:  java.io.PrintWriter error");

            /* read response */
            BufferedReader in = new BufferedReader(
                                    new InputStreamReader(
                                    socket.getInputStream()));

            String inputLine;
			/*
			 * while ((inputLine = in.readLine()) != null) System.out.println(inputLine);
			 */

            in.close();
            out.close();
            socket.close();
            
			TimeUnit.SECONDS.sleep(3);
			
		}
		catch( Exception e) {
			System.out.println(e.getLocalizedMessage()+e.getMessage()+e.getLocalizedMessage());
		}
		//temp location of method.. 
		//TODO: move to TLS_Connection ended
		connectionTerminated();
		return;
	}
	
	private void connectionTerminated() {
		logger.onConnectionEndSuccessfully(id, "terminating succesfully",System.currentTimeMillis());
	}
	
}
