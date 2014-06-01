package com.pycto.applet;

import java.applet.Applet;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class EVotoApplet extends Applet {

	@Override
	public void start() {
		// TODO Auto-generated method stub
		super.start();
		
		
		setBackground(Color.BLUE);						
		setSize(new Dimension(1024,400));
		
		try {

			//*********************** SETUP **********************************

			RSAPublicKey pubKey;
			RSAPrivateKey privKey;

			//generate the RSA key pair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			//initialise the KeyGenerator with a random number.
			keyGen.initialize(1024, new SecureRandom());
			KeyPair keypair = keyGen.genKeyPair();
			
			
			privKey = (RSAPrivateKey)keypair.getPrivate();
			pubKey = (RSAPublicKey)keypair.getPublic();

			String message = "LALALLALAL";
			byte [] raw = message.getBytes("UTF8");

			BigInteger m = new BigInteger(raw);
			BigInteger e = pubKey.getPublicExponent();
			BigInteger d = privKey.getPrivateExponent();

			SecureRandom random = SecureRandom.getInstance("SHA1PRNG","SUN");
			byte [] randomBytes = new byte[10];
			BigInteger r = null;
			BigInteger n = pubKey.getModulus();
			BigInteger gcd = null;
			BigInteger one = new BigInteger("1");
			
			//check that gcd(r,n) = 1 && r < n && r > 1
			do {
				random.nextBytes(randomBytes);
				r = new BigInteger(1, randomBytes);
				gcd = r.gcd(n);
				System.out.println("gcd: " + gcd);
			}
			while(!gcd.equals(one) || r.compareTo(n)>=0 || r.compareTo(one)<=0);

			//********************* BLIND ************************************

			BigInteger b = ((r.modPow(e,n)).multiply(m)).mod(n);
			System.out.println("\nb = " + b);
			//must use modPow() - takes an eternity to compute:
			//b = ((r.pow(e.intValue)).multiply(m)).mod(n);

			//********************* SIGN *************************************

			BigInteger bs = b.modPow(d,n);
			System.out.println("bs = " + bs);

			//********************* UNBLIND **********************************

			BigInteger s = r.modInverse(n).multiply(bs).mod(n);
			System.out.println("s = " + s);

			//********************* VERIFY ***********************************

			//signature of m should = (m^d) mod n
			BigInteger sig_of_m = m.modPow(d,n);
			System.out.println("sig_of_m = " + sig_of_m);

			//check that s is equal to a signature of m:
			System.out.println(s.equals(sig_of_m));

			//try to verify using the RSA formula
			BigInteger check = s.modPow(e,n);
			System.out.println(m.equals(check));

			//BOTH TESTS RETURN FALSE - s must not be a valid signature of m 
		}
		catch(Exception ex) {
			System.out.println("ERROR: ");
			ex.printStackTrace();
		}
	}
	
	@Override
	public void paint(Graphics g) {
	// TODO Auto-generated method stub
	super.paint(g);
	
	g.setColor(Color.WHITE);
    g.drawString("Esta a punto de votar la imagen", 400, 50);
    
	}


}

