package com.example.samplesimpleclientcertificateapp;

import static android.support.v7.security.KeyChain.EXTRA_PKCS12;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.security.KeyChain;
import android.support.v7.security.KeyChainCallBack;
import android.support.v7.security.KeyChainException;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.Window;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends Activity
{
	private static final String TAG="TAG";
	
	/** Implementation name for TLS */
	private static final String TLS_IMPLEMENTATION_ALGORITHM	="TLS";
	// BUG with provider "AndroidOpenSSL" with Android 4.x
	private static final String TLS_IMPLEMENTATION_PROVIDER		=null; //"HarmonyJSSE"; // "AndroidOpenSSL"; // "BC", // "DRLCertFactory", // "Crypto"
	/** Secure random algorithm. */
    private static final String SECURE_RANDOM_ALGORITHM			="SHA1PRNG";

	/** Default alias name. */
	private static final String ALIAS_KEY="alias";
	/** Default alias name. */
	private static final String ALIAS="customer";
	
	/** Asset file name with a sample client certificat. */
	private static final String PKCS12_CLIENT_FILENAME="client.p12";
	/** Password of the PKCS12_FILENAME */
	private static final String PKCS12_CLIENT_PASSWORD="tomcat";

	// Want to install certificat, but unlock the key store before
	private static final int STATE_INSTALL=1;
	// Want to use certificat, but unlock the key store before
	private static final int STATE_USE=2;
	
	// Current state. Zero if no pending usage.
	private int mState=0;
	// Extra to save the mState
	private static final String EXTRA_STATE="state";
	
	private final Handler mHandler=new Handler();
	private EditText mHostPort;
	
	private SharedPreferences mPreference;
	private KeyChain mKeyChain;
	private String mAlias;
	private SSLSocketFactory mSocketFactory;

	final KeyManager[] keyManagers=new KeyManager[]
			{
				new X509KeyManager()
				{
					@Override
					public String[] getServerAliases(String keyType, Principal[] issuers)
					{
						return null;
					}
					@Override
					public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
					{
						return null;
					}
					
					@Override
					public String[] getClientAliases(String keyType, Principal[] issuers)
					{
						return new String[]{mAlias};
					}
					@Override
					public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
					{
						return mAlias;
					}
					
					@Override
					public X509Certificate[] getCertificateChain(String alias)
					{
						try
						{
							return mKeyChain.getCertificateChain(MainActivity.this, mAlias);
						}
						catch (KeyChainException e)
						{
							e.printStackTrace();
							return null; // FIXME: accept null ?
						}
						catch (InterruptedException e)
						{
							e.printStackTrace();
							return null;
						}
						catch (Exception e) // FIXME
						{
							e.printStackTrace();
							return null;
						}
					}
					@Override
					public PrivateKey getPrivateKey(String alias)
					{
						try
						{
							return mKeyChain.getPrivateKey(MainActivity.this, mAlias);
						}
						catch (KeyChainException e)
						{
							return null;
						}
						catch (InterruptedException e)
						{
							return null;
						}
						catch (Exception e) // FIXME
						{
							return null;
						}
					}
				}
			};
	private static final byte[] FINGERPRINT=new byte[]{-122,-119,93,98,63,-106,-82,-71,23,42,98,96,-18,-50,-106,-108,};
	
	final X509TrustManager[] X509TrustManager=
    		new X509TrustManager[]
			{ 
				new X509TrustManager()
				{
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
					{
						Log.v(TAG,"check client trusted");
					}
		
					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
					{
						Log.v(TAG,"check server trusted");

						try
						{
							byte[] currentDigest = MessageDigest.getInstance("SHA-1").digest(chain[0].getEncoded());
							if (!Arrays.equals(FINGERPRINT, currentDigest))
								throw new CertificateException("Invalid server certificate");
							//StringBuilder buf=new StringBuilder("private static final byte[] DIGEST=new byte[]{");
							//for (int i=0;i<currentDigest.length;++i) buf.append(currentDigest[i]).append(",");
							//buf.append("};");
							//Log.d(TAG,buf.toString());
						}
						catch (NoSuchAlgorithmException e)
						{
							throw new CertificateException("Invalid server certificate");
						}
						
					}
		
					@Override
					public X509Certificate[] getAcceptedIssuers()
					{
						return new X509Certificate[0];
					}
				} 
			};

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		if (savedInstanceState!=null)
		{
			mState=savedInstanceState.getInt(EXTRA_STATE);
		}
		mPreference=getPreferences(Context.MODE_PRIVATE);
		mAlias=mPreference.getString(ALIAS_KEY, ALIAS);
		mKeyChain=new KeyChain(this);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		setProgressBarIndeterminateVisibility(false);		
		setContentView(R.layout.activity_main);
		mHostPort=(EditText)findViewById(R.id.hostport);
	}

	@Override
	protected void onResume()
	{
		super.onResume();
		// Switch the current state, after unlock the key store, continue the job
		switch (mState)
		{
			case STATE_INSTALL:
				installCertificate(null);
				break;
			case STATE_USE:
				useCertificate(null);
				break;
			default:
				break;
		}
	}
	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_main, menu);
		return true;
	}
	
	@Override
	protected void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putInt(EXTRA_STATE, mState);
	}
	public void installCertificate(View view)
	{
		if (!mKeyChain.isUnLocked())
		{
			// Key store is locked. Start an activity to unlock it.
			mState=STATE_INSTALL;
			mKeyChain.unlock(this);
		}
		else
		{
			mState=0;
			new AsyncTask<Void, Void, byte[]>()
			{
				@Override
				protected void onPreExecute() 
				{
					setProgressBarIndeterminateVisibility(true);		
				}
				@Override
				protected byte[] doInBackground(Void... params)
				{
					try
					{
						InputStream in=getAssets().open(PKCS12_CLIENT_FILENAME);
						ByteArrayOutputStream out=new ByteArrayOutputStream();
						byte[] buf=new byte[4096];
						int l;
						while ((l=in.read(buf))>0)
						{
							out.write(buf,0,l);
						}
						out.close();
						in.close();
						return out.toByteArray();
					}
					catch (IOException e)
					{
						throw new Error(e);
					}
				}
				@Override
				protected void onPostExecute(byte[] pkcs12) 
				{
					try
					{
						setProgressBarIndeterminateVisibility(false);		
				    	Intent intent=mKeyChain.createInstallIntent();
						//intent.putExtra(EXTRA_NAME, mAlias);
						intent.putExtra(EXTRA_PKCS12, pkcs12);
						startActivity(intent);
					}
					finally {} // FIXME
				}
			}.execute();
		}
	}
	public void chooseCertificate(View view)
	{
		mKeyChain.choosePrivateKeyAlias(this, 
				new KeyChainCallBack()
				{

					@Override
					public void alias(final String alias)
					{
						if (alias!=null)
						{
							mAlias=alias;
							Log.d(TAG,"Use alias \""+alias+'"');
							// Save last alias
							mPreference.edit().putString(ALIAS_KEY, alias).commit();
							mHandler.post(new Runnable()
							{
								@Override
								public void run()
								{
									Toast.makeText(MainActivity.this, String.format(getString(R.string.use_alias),alias), Toast.LENGTH_LONG).show();
								}
							});
						}
					}
					
				}, 
			    null,//new String[] {"RSA", "DSA"}, 	// List of acceptable key types. null for any
			    null,                        				// issuer, null for any
			    null,//"internal.example.com",     		// host name of server requesting the cert, null if unavailable
			    -1,                         				// port of server requesting the cert, -1 if unavailable
			    null);//CERT_NAME);                     // alias to preselect, null if unavailable
	}
	public void useCertificate(View view)
	{
		if (!mKeyChain.isUnLocked())
		{
			// Key store is locked. Start an activity to unlock it.
			mState=STATE_USE;
			mKeyChain.unlock(this);
			return;
		}

		mState=0;
		new AsyncTask<Void,Void,Boolean>()
		{
			String mHost;
			int mPort;
			
			@Override
			protected void onPreExecute() 
			{
				setProgressBarIndeterminateVisibility(true);		
				mHost=mHostPort.getText().toString();
				int idx=mHost.indexOf(':');
				if (idx!=-1)
				{
					try
					{
						mPort=Integer.parseInt(mHost.substring(idx+1));
						mHost=mHost.substring(0,idx);
					} catch (NumberFormatException e)
					{
						// Ignore
					}
				}
				else
					mPort=443;
			}
			// Installation d'un certificat
			@Override
			protected Boolean doInBackground(Void... params)
			{
				try
				{
					// Recycle the socket factory ?
					if (mSocketFactory==null)
					{
						final SSLContext sslcontext =
								(TLS_IMPLEMENTATION_PROVIDER==null) 
								? SSLContext.getInstance(TLS_IMPLEMENTATION_ALGORITHM)
								: SSLContext.getInstance(TLS_IMPLEMENTATION_ALGORITHM, TLS_IMPLEMENTATION_PROVIDER);
						SecureRandom random=SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
						sslcontext.init(
							keyManagers,
							X509TrustManager, 
							random);
						mSocketFactory=sslcontext.getSocketFactory();
					}

					// Use with SSLSocket
					{
						SSLSocket socket=(SSLSocket)mSocketFactory.createSocket();
						socket.connect(new InetSocketAddress(mHost,mPort),10000);
						PrintWriter out=new PrintWriter(socket.getOutputStream());
						BufferedReader in=new BufferedReader(new InputStreamReader(socket.getInputStream()));
						out.write("GET / HTTP/1.0\n\n");
						out.flush();
						System.out.println(in.readLine());
						System.out.println(socket.getSession().getPeerCertificates());
						//Principal principal=socket.getSession().getPeerPrincipal();	System.out.println(principal);
						socket.close();
					}
					
					// Use certificate with HTTPS
					{
						HttpsURLConnection.setDefaultSSLSocketFactory(mSocketFactory);
					    HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
						{
					        @Override
							public boolean verify(String hostname, SSLSession session) 
					        {
					          return true;
					        }
					    });
	
						URLConnection con=new URL("https://"+mHost+":"+mPort+"/").openConnection();
						BufferedReader in=new BufferedReader(new InputStreamReader(con.getInputStream()));
						in.readLine();
					}
					return Boolean.TRUE;
				}
				catch (Exception e) // FIXME
				{
					e.printStackTrace();
					return Boolean.FALSE;
				}
			}
			@Override
			protected void onPostExecute(Boolean result) 
			{
				setProgressBarIndeterminateVisibility(false);		
				Toast.makeText(MainActivity.this,(result) ? R.string.connection_ok : R.string.connection_fail, Toast.LENGTH_LONG).show();
			}
		}.execute();
		
	}
	
}
