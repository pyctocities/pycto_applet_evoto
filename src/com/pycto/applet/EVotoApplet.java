package com.pycto.applet;

import java.applet.Applet;
import java.awt.Button;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Event;
import java.awt.Graphics;
import java.awt.Label;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import com.google.gson.Gson;

public class EVotoApplet extends Applet {

	public RSAPublicKey pubKey;
	public RSAPrivateKey privKey;
	public CSR request_cert = new CSR();
	
	
	public TextField user;
	public TextField pass;
	public TextField id_foto;
	public Button okButton; 
	public Label userlabel = new Label("Usuario: ");
	public Label passlabel = new Label("Password: ");
	public Label idfotolabel = new Label("Id foto: ");
	public Label titol = new Label("VOTACIÓN ELECTRONICA");
	ApiPycto api;


	@Override
	public void start() {
		// TODO Auto-generated method stub
		super.start();

		api = new ApiPycto();

		setBackground(Color.decode("#6D91B4"));		
		//setSize(new Dimension(1024,400));
		setSize(new Dimension(450,300));
		setLayout(null); 

		user = new TextField(30);
		pass = new TextField(30);
		id_foto = new TextField(30);
		okButton = new Button("Votar!"); 

		titol.setBounds(150,30,200,20);
		titol.setForeground(Color.RED);

		userlabel.setBounds(50,85,50,20);
		user.setBounds(150,85,200,20);
		user.setVisible(true);

		passlabel.setBounds(50,135,60,20);
		pass.setBounds(150,135,200,20);
		pass.setEchoChar('*');

		idfotolabel.setBounds(50,185,50,20);
		id_foto.setBounds(150,185,200,20);

		okButton.setBounds(150,230,100,20);
		okButton.addActionListener(l);

		add(titol);
		add(userlabel);
		add(user);
		add(passlabel);
		add(pass);
		add(idfotolabel);
		add(id_foto);
		add(okButton);
		
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024, new SecureRandom());
			KeyPair keypair = keyGen.genKeyPair();

			privKey = (RSAPrivateKey)keypair.getPrivate();
			pubKey = (RSAPublicKey)keypair.getPublic();

			request_cert.setId(Integer.toString(1));
			request_cert.setPubKey(pubKey.getEncoded());
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//initialise the KeyGenerator with a random number.

	}

	@Override
	public void paint(Graphics g) {
		// TODO Auto-generated method stub
		super.paint(g);
		g.setColor(Color.WHITE);
		// g.drawString("VOTACIÓN DE IMAGEN", 200, 20);


	}
	
	//ESte listener es para cuando se apreta el boton de votar

	public ActionListener l = new ActionListener() {

		@Override
		public void actionPerformed(ActionEvent e) {
			//vota();

			if(api.login(user.getText(), pass.getText())) //Si el login es correcto, pide la firma primero de todo
			{
				try {
					String result = api.pedir_firmar_CSR_cegado(user.getText(),privKey,pubKey);
					BigInteger csr_firmado = new BigInteger(result);
					
					JOptionPane.showMessageDialog(null, csr_firmado.toString()); //Aqui se muestra el biginteger firmado
					System.out.println("Pseudonim recent firmat: "+csr_firmado);

					String fotos = id_foto.getText();

					String idfotos[] = fotos.split(",");

					if(idfotos.length==5){  //Estan las 5 fotos bien puestas (ejemplo: 1,2,3,4,5)
						
						
						//1º - JSON de votos en claro con las ids de las fotos
						String json_id_fotos =idfotos[0]
								+"&"+idfotos[1]
								+"&"+idfotos[2]
								+"&"+idfotos[3]
								+"&"+idfotos[4];						
						
						//2º- HASH de las ids de las fotos encriptado con la clave privada del usuario
						MessageDigest md = null;
						BigInteger HASH_json_id_fotos = null;
						
						try {
							md = MessageDigest.getInstance("SHA-1");
							md.update(json_id_fotos.getBytes());
							byte[] passbytes = md.digest();
							HASH_json_id_fotos = new BigInteger(1,passbytes);
							
						} catch (NoSuchAlgorithmException e1) {
							e1.printStackTrace();
						}
						
						BigInteger n = pubKey.getModulus();
						BigInteger d = privKey.getPrivateExponent();
						
						BigInteger hash_id_fotos_firmado = HASH_json_id_fotos.modPow(d,n);

						
						
						//3º- Pseudonimo del usuario en claro
						
						BigInteger pseudonimo_usuario = pseudonimo_cegado();
						System.out.println("Pseudonim que es fa segona vegada sense firmar: "+pseudonimo_usuario);
						
						//4º- Clave publica usuario en claro. La clave publica se divide en dos BigIntegers: 
						//el exponente publico y el modulo.Nosotros lo separaremos por doble coma ",,"
						
						BigInteger exponente_public = pubKey.getPublicExponent();
						BigInteger modulo = pubKey.getModulus();
						
						String exponente_publico_i_modulo = exponente_public.toString() + ".."+modulo;
						
						//5º- Pseudonimo+clavepublica hasheado y firmado con la privada de la CA (es el que hemos pedido anteriormente
						
						String pseudonimo_clavepubli_hasheado_firmadoCA = csr_firmado.toString();
						
						//Formato de datos a enviar:
						
						String voto_enviar = 
								json_id_fotos+"-"
								+hash_id_fotos_firmado+"-"
								+pseudonimo_usuario+"-"
								+exponente_publico_i_modulo+"-"
								+pseudonimo_clavepubli_hasheado_firmadoCA;
						
						System.out.println("\n Resultado a enviar: "+voto_enviar);
						
						
						String re = api.vote(voto_enviar);
						JOptionPane.showMessageDialog(null, "La votacio ha salido: "+re);
	
					}
					else
					{
						JOptionPane.showMessageDialog(null, "Has de votar 5 fotos");
					}



				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (UnsupportedEncodingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
			else
			{
				JOptionPane.showMessageDialog(null, "Usuario/Contraseña incorrectos!");

			}


		}
	};
	
	public BigInteger pseudonimo_cegado() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException{
		
		request_cert.setId(user.getText());
		request_cert.setPubKey(pubKey.getEncoded());
		
		Gson j = new Gson();
		String pseudonimo_sin_blindar = j.toJson(request_cert);

		String message = pseudonimo_sin_blindar;
		
		BigInteger e = pubKey.getPublicExponent();
		BigInteger d = privKey.getPrivateExponent();
		
		MessageDigest md = null;
		BigInteger pseudonim_cegado2 = null;
		
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(pseudonimo_sin_blindar.getBytes());
			byte[] passbytes = md.digest();
			pseudonim_cegado2 = new BigInteger(1,passbytes);
			
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		//********************* CEGADO ************************************

		BigInteger pseudonimo_cegado = pseudonim_cegado2.multiply(new BigInteger("1111111111111111111111111111"));
		
		return pseudonimo_cegado;
		
	}

	public void vota (){
		try {

			//generate the RSA key pair

			Gson j = new Gson();
			String pseudonimo_sin_blindar = j.toJson(request_cert);

			String message = pseudonimo_sin_blindar;
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

			//********************* CEGADO ************************************

			BigInteger pseudonimo_cegado = ((r.modPow(e,n)).multiply(m)).mod(n);
			System.out.println("\nb = " + pseudonimo_cegado);
			//must use modPow() - takes an eternity to compute:
			//b = ((r.pow(e.intValue)).multiply(m)).mod(n);

			//********************* FIRMA (sera la de la CA, ahora es la del mismo usuario, es para ver como se firma) *************************************

			BigInteger pseudonimo_cegado_signado = pseudonimo_cegado.modPow(d,n);
			System.out.println("bs = " + pseudonimo_cegado_signado);

			//********************* DESCEGADO **********************************

			BigInteger pseudonimo_descegado = r.modInverse(n).multiply(pseudonimo_cegado_signado).mod(n);
			System.out.println("s = " + pseudonimo_descegado);

			//********************* VERIFICACIÓN ***********************************

			//LA signatura de M deberia ser = (m^d) mod n
			BigInteger sig_of_m = m.modPow(d,n);
			System.out.println("sig_of_m = " + sig_of_m);

			//Mirar si la signatura es la misma
			System.out.println(pseudonimo_descegado.equals(sig_of_m));

		}
		catch(Exception ex) {
			System.out.println("ERROR: ");
			ex.printStackTrace();
		}

	}



}

