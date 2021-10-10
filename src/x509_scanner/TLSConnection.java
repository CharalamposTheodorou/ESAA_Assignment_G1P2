package x509_scanner;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import x509_scanner.ConnectionHandler.ConnectionLogger;

import java.net.*;
import java.security.Principal;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.*;
import java.lang.reflect.Field;

import javax.net.ssl.*;
import static x509_scanner.ConnectionHandler.rootstore_list;
import static x509_scanner.ConnectionHandler.trustedCertificates;

import org.certificatetransparency.ctlog.proto.Ct;

import sun.security.provider.certpath.SunCertPathBuilderException;

public class TLSConnection implements Runnable {
	
	/**
	 * Interface to handle the messages/responses and Errors of the TLS connection
	 * Returns log information to the ConnectionHandler class
	 * Returns all responses and messages received
	 * @author USER
	 *
	 */
	public interface ConnectionInterface {
		
		public static final String CT_LOG_TAG = "ct_logs"; //number of ct logs in chain
		public static final String VALID_TAG = "valid";//boolean if valid or not in the chain
		public static final String CA_NAME = "ca_name";//CA who was validated in chain
		public static final String ERROR = "error"; //error message in connection. termination..
		
//		void onThreadStart(int id, String message, long timestamp);
//		
//
//		void onThreadEnd(int id, String message, long timestamp);
//		
//		/*
//		 * Returns on the implementing class the data from the successful connection End
//		 */
//		void onConnectionEndSuccessfully(int id, String message, long timestamp);
//		
//
//		/*
//		 * Returns on the implementing class the data from the failed connection End
//		 */
//		void onConnectionEndFailure(int id, String message, long timestamp, String error);
//		
//
//		/*
//		 * Returns on the implementing class the data from the successful connection Start
//		 */
//		void onConnectionStartSuccessfully(int id, String message, long timestamp);
//		
//
//		/*
//		 * Returns on the implementing class the data from the failed connection Start
//		 */
//		void onConnectionStartFailure(int id, String message, long timestamp, String error);
//		
//
//		/*
//		 * Returns on the implementing class the data from the message
//		 */
//		void onMessageLog(int id, String message, long timestamp,String tag, String value);
		
		void onSendLogs(int logs_counter, boolean validated, String valid_CA, String error, String description, int version);
	}
	
	private int id;
	private long timestampStart;
	private long timestampEnd;
	private String domain;
	private String IP;
	private SSLSocket socket;
	
	
	private ConnectionInterface logger;
	//Protocols supported for certificate
	private static final String[] protocols = new String[] {"TLSv1.1","TLSv1.2","TLSv1.3"};
	//algorithmic ciphers supported
    private static final String[] cipher_suites = new String[] {"TLS_AES_128_GCM_SHA256"};
    
    private int logs_counter;
    private boolean validated;
    private String valid_CA;
    private String error;
    private String description;
	private int version;
    
	public TLSConnection(int id, String ip, String domain, /* String version, */ ConnectionLogger logger) {
		this.id = id;
		this.IP = ip;
		//this.version = version;
		this.domain = domain;
		this.logger = logger;
		this.logs_counter = 0;
		this.validated = false;
		this.error = "";
		this.valid_CA = "";
		this.description = "";
	}
	
	@Override
	public void run() {
		try {
			//TODO:remove below?
			//logger.onThreadStart(id,"new Thread: ID: "+id+", started on:", System.currentTimeMillis());
			//initiating SSL connection process..
			SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			socket = (SSLSocket)factory.createSocket(this.domain,443);
		    socket.setEnabledProtocols(protocols);
		    
		    socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
		    	@Override
			    public void handshakeCompleted(HandshakeCompletedEvent event) {
			    	// TODO Auto-generated method stub
		    		SSLSocket socket = event.getSocket();
					SSLSession session = event.getSession();
					//TODO: check session?
					try {
						//TODO: write and name of issuer to logger and everything else relevant
						//javax.security.cert.X509Certificate[] certs = event.getPeerCertificateChain();
						
						Certificate[] certs = event.getPeerCertificates();
						boolean verified = false;
						//Logging the number of CT logs
						//logger.onMessageLog(id, certs.length+" CT Logs", System.currentTimeMillis(),ConnectionInterface.CT_LOG_TAG,String.valueOf(certs.length));
						logs_counter = certs.length;
						for (int i=0; i<certs.length-1; i++ ) {
							verified = false;
							X509Certificate cert = (X509Certificate)certs[i];
							X509Certificate issuer = (X509Certificate)certs[i+1];
							//logging the CA name for this certificate
							//TODO: remove?
							//logger.onMessageLog(id, "CA NAME:"+issuer, System.currentTimeMillis(),ConnectionInterface.CA_NAME,issuer.toString());
							//TODO: do nothing remove above.
							//try {

								if (cert.getIssuerX500Principal().equals(issuer.getIssuerX500Principal())) {
									try {

										cert.verify(issuer.getPublicKey());
										verified = true;//TODO:Check Issuer correctly get name.
										//TODO: verified must be true to proceed..
//										logger.onMessageLog(id,"Trusted CA:"+trusted.toString(), System.currentTimeMillis(),ConnectionInterface.CA_NAME, trusted.toString());
//										logger.onMessageLog(id,"Certificate is valid", System.currentTimeMillis(),ConnectionInterface.VALID_TAG, String.valueOf(true));
//										logger.onMessageLog(id,"CA is valid", System.currentTimeMillis(),ConnectionInterface.VALID_CA, String.valueOf(true));
									} catch (Exception ignore) {
										verified = false;
									} finally {
										System.out.println("domain:"+ domain+" Verified:"+verified);
										if (verified) {
											System.out.println("************ Verified ************\n issuer:");
											System.out.println("string:"+issuer.getIssuerDN().toString()+".");
											valid_CA = issuer.getIssuerDN().toString(); //TODO: check for issuer
											//logger.onMessageLog(id,"Chain is Verified by CA:", System.currentTimeMillis(), ConnectionInterface.CA_NAME, issuer.toString());
											validated = true;
											description = "Certificate validated by:"+valid_CA;
											version = issuer.getVersion();
											//logger.onMessageLog(id,"Certificate is valid", System.currentTimeMillis(),ConnectionInterface.VALID_TAG, String.valueOf(true));
										}
									}
								}
						}
						//TODO: maybe remove?
						if (!verified) {
							//check with root-store values
							for (int i=0; i<certs.length; i++) {
								X509Certificate cert = (X509Certificate)certs[i];
								
								for (int j=0; j<trustedCertificates.size(); j++) {
									
									X509Certificate trusted = trustedCertificates.get(j);
									if (cert.getIssuerX500Principal().equals(trusted.getIssuerX500Principal())) {
										try {
											cert.verify(trusted.getPublicKey());
											
											verified = true;
										} catch (Exception ignore) {
											verified = false;
										} finally {
											System.out.println("domain:"+ domain+" Verified:"+verified);
											if (verified) {
												System.out.println("************ Verified ************\n trusted:");
												System.out.println("string:"+trusted.getIssuerDN().toString()+".");
												valid_CA = trusted.getIssuerDN().toString();
												//logger.onMessageLog(id,"Trusted CA:"+trusted.toString(), System.currentTimeMillis(),ConnectionInterface.CA_NAME, trusted.toString());
												validated = true;
												version = trusted.getVersion();
												description = "Certificate validated by:"+valid_CA+" from root store";
												//logger.onMessageLog(id,"Certificate is valid", System.currentTimeMillis(),ConnectionInterface.VALID_TAG, String.valueOf(true));
											}
										}

									}
								}
							}
						}
						if (!verified) {
							X509Certificate last = (X509Certificate)certs[certs.length-1];
							if (last.getIssuerX500Principal().equals(last.getIssuerX500Principal())) {
								try {
									//verify with self-sign.
									last.verify(last.getPublicKey());
									verified = true;
								} catch (Exception ignore) {
									verified = false;
								} finally {
									System.out.println("domain:"+ domain+" Verified:"+verified);
									if (verified) {
										System.out.println("************ Verified ************\n self:");
										System.out.println("string:"+last.getIssuerDN().toString()+".");
										version = -1;
										validated = true;
										description = "Certificate self-validated.";

										//logger.onMessageLog(id,"Certificate is self-signed (last)", System.currentTimeMillis(),ConnectionInterface.VALID_TAG, String.valueOf(true));//TODO: if no value for VALID_CA -> self sign
									}
								}						
							}
						}
						
						if (!verified) {
							System.out.println("it's not verified");
							//logger.onMessageLog(id,"Certificate is valid", System.currentTimeMillis(),ConnectionInterface.VALID_TAG, String.valueOf(false));
							validated = false;
							description = "Not validated by chain or root store or self";
						}
					} catch (SSLPeerUnverifiedException e) {
						// TODO Auto-generated catch block
						//TODO: check this error: logger.onMessageLog(id,"Certificate is not valid:"+e.getMessage(), System.currentTimeMillis(),ConnectionInterface.VALID_CA, String.valueOf(false));
						error = e.getMessage();
						description = "Exception:"+e.getLocalizedMessage();
						System.out.println("SSL:"+e.getMessage());
					} 
					catch(Exception e) {
						//TODO:check this -> logger.onMessageLog(id,"Certificate is not valid:"+e.getMessage(), System.currentTimeMillis(),ConnectionInterface.VALID_CA, String.valueOf(false));
						error = e.getMessage();
						description = "Exception:"+e.getLocalizedMessage();
						System.out.println("E: "+e.getMessage());
					}
					
			    }
		    });
		    
		    socket.startHandshake();

			BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                    socket.getInputStream()));

			String inputLine;
			/*
			 * while ((inputLine = in.readLine()) != null) {
			 * 
			 * System.out.println("Input:"+inputLine); this.logger.onMessageLog(this.id,
			 * inputLine, System.currentTimeMillis()); }
			 */
			in.close();	
			
		} 
		catch( Exception e) {
		}
		finally {
			try {	
				socket.close();
			} catch(NullPointerException e) {
				error = e.getMessage();
				description = "Exception:"+e.getLocalizedMessage();
			}
			catch (IOException e) {
				error = e.getMessage();
				description = "Exception:"+e.getLocalizedMessage();
			}
			catch (Exception e) {}
			finally {
				this.logger.onSendLogs(logs_counter,validated, valid_CA, error, description,version);
			}
		}
	}	
}
