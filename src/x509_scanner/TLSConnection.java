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
    
	public TLSConnection(int id, String ip, String domain, ConnectionLogger logger) {
		this.id = id;
		this.IP = ip;
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
			SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			socket = (SSLSocket)factory.createSocket(this.domain,443);
		    socket.setEnabledProtocols(protocols);
		    
		    socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
		    	@Override
			    public void handshakeCompleted(HandshakeCompletedEvent event) {
					try {
						//triggered for completed handshake 
						//getting the certificate chain:
						Certificate[] certs = event.getPeerCertificates();
						boolean verified = false;

						//CT Logs for this respose
						logs_counter = certs.length;
						
						//looping the chain to find if verified
						for (int i=0; i<certs.length-1; i++ ) {
							verified = false;
							//sequencial logs in the certificate chain
							X509Certificate cert = (X509Certificate)certs[i];
							X509Certificate issuer = (X509Certificate)certs[i+1];
							
								if (cert.getIssuerX500Principal().equals(issuer.getIssuerX500Principal())) {
									try {
										//checking if verifying the Certificate with the issuer Public Key
										cert.verify(issuer.getPublicKey());
										verified = true;
									} catch (Exception ignore) {
										verified = false;
									} finally {
										if (verified) {
											//Setting values to the logger
											valid_CA = issuer.getIssuerDN().toString(); 
											validated = true;
											description = "Certificate validated by:"+valid_CA;
											version = issuer.getVersion();
										}
									}
								}
						}
						if (!verified) {
							//check with root-store values
							for (int i=0; i<certs.length; i++) {
								//Certificates in the chain
								X509Certificate cert = (X509Certificate)certs[i];
								
								for (int j=0; j<trustedCertificates.size(); j++) {
									//looping in root-store certificates
									X509Certificate trusted = trustedCertificates.get(j);
									if (cert.getIssuerX500Principal().equals(trusted.getIssuerX500Principal())) {
										try {
											//checking if verifying the Certificate with the root-store Public Key
											cert.verify(trusted.getPublicKey());
											verified = true;
										} catch (Exception ignore) {
											verified = false;
										} finally {
											if (verified) {
												//Setting values to the logger
												valid_CA = trusted.getIssuerDN().toString();
												validated = true;
												version = trusted.getVersion();
												description = "Certificate validated by:"+valid_CA+" from root store";
											}
										}

									}
								}
							}
						}
						//checking with self-sign
						if (!verified) {
							//get last in the chain to check for self-sign certificate
							X509Certificate last = (X509Certificate)certs[certs.length-1];
							if (last.getIssuerX500Principal().equals(last.getIssuerX500Principal())) {
								try {
									//verify with self-sign.
									last.verify(last.getPublicKey());
									verified = true;
								} catch (Exception ignore) {
									verified = false;
								} finally {
									if (verified) {
										//Setting values to the logger
										version = -1;
										validated = true;
										description = "Certificate self-validated.";
									}
								}						
							}
						}
						
						if (!verified) {
							validated = false;
							description = "Not validated by chain or root store or self";
						}
					} catch (SSLPeerUnverifiedException e) {
						error = e.getMessage();
						description = "Exception:"+e.getLocalizedMessage();
						System.out.println("SSL:"+e.getMessage());
					} 
					catch(Exception e) {
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
