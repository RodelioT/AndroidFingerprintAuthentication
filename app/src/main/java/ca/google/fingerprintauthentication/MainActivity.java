package ca.google.fingerprintauthentication;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_NAME = "yourKey"; // Key used for fingerprint authentication
    private Cipher cipher;                          // Used for creating the cryptoObject instance
    private KeyStore keyStore;                      // Contains all the cryptographic keys
    private KeyGenerator keyGenerator;              // Generates a cryptographic key that is used by this app
    private TextView textView;
    private FingerprintManager.CryptoObject cryptoObject; // Used by the FingerprintManager
    private FingerprintManager fingerprintManager;  // Handles the actual fingerprint authentication
    private KeyguardManager keyguardManager;        // Used to to check if the user has a lockscreen lock

    private boolean fingerprintsAvailable = false;

    // Use the CancellationSignal method whenever your app can no longer process user input (ex: when your app goes into the background)
    // If you don’t use this method, then other apps will be unable to access the touch sensor, including the lockscreen!
    private CancellationSignal cancellationSignal;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Checks to see if the device's SKD level is at least 23 (Marshmallow),
        //   before dealing with anything fingerprint related.
        //   Alternatively, you can set the Minimum SDK level of the app to 23.
        if (Build.VERSION.SDK_INT >= 23) {
            // Gets an instance of KeyguardManager and FingerprintManager
            keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

            textView = findViewById(R.id.textview);

            // Check whether the device has a fingerprint sensor
            if (!fingerprintManager.isHardwareDetected()) {
                textView.setText("Your device doesn't support fingerprint authentication");

            //Check if the lockscreen is secured (required to store fingerprints)
            } else if (!keyguardManager.isKeyguardSecure()) {
                textView.setText("Please enable lockscreen security in your device's Settings");

            // Checks if at least 1 fingerprint is registered
            } else if (!fingerprintManager.hasEnrolledFingerprints()) {
                textView.setText("You don't have any fingerprints saved. Go to\n[Settings -> Security -> Fingerprint]\nand set up at least 1 fingerprint.");

            // Checks if the user has allowed for the app to use fingerprint permissions
            } else if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                textView.setText("Please enable fingerprint permissions");

            // Sets the flag to true if all checks passed
            } else {
                fingerprintsAvailable = true;
            }
        }

        // If all checks are positive
        if (fingerprintsAvailable) {
            try {
                generateKey();
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (initCipher()) {
                //If the cipher is initialized successfully, then create a CryptoObject instance//
                cryptoObject = new FingerprintManager.CryptoObject(cipher);

                // Instantiates a new FingerprintHandler Class
                FingerprintHandler helperClass = new FingerprintHandler();
                helperClass.startAuth(fingerprintManager, cryptoObject);
            }
        }
    }



    // Method that will be used to gain access to the Android keystore and generate the encryption key
    private void generateKey() throws Exception {
        try {
            // Obtain a reference to the Keystore using the standard Android keystore container identifier (“AndroidKeystore”)
            keyStore = KeyStore.getInstance("AndroidKeyStore");

            // Generate a key
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            // Initialize an empty KeyStore
            keyStore.load(null);

            // Initialize the KeyGenerator key with these parameters
            keyGenerator.init(new
                    //Specify the operation(s) this key can be used for//
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

                    //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            //Generate the key//
            keyGenerator.generateKey();

        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | IOException exc) {
            exc.printStackTrace();
            throw new Exception(exc);
        }
    }

    // Method that is used to initialize the cipher
    public boolean initCipher() {
        try {
            // Obtain a cipher instance and configure it with the properties required for fingerprint authentication
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // Return true if the cipher has been initialized successfully
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {

            //Return false if cipher initialization failed//
            return false;
        } catch (KeyStoreException | CertificateException
                | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    // Class that handles the process of scanning a fingerprint
    //   Has overwritten methods to perform actions when a finger is scanned (toasts in this example)
    public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

        // Method responsible for starting the fingerprint authentication process
        void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {
            cancellationSignal = new CancellationSignal();

            if (ActivityCompat.checkSelfPermission(MainActivity.this, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED) {
                manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
            }
        }

        @Override
        // Occurs when a fingerprint has been scanned and is not recognized
        public void onAuthenticationFailed() {
            Toast.makeText(MainActivity.this, "Authentication failed", Toast.LENGTH_LONG).show();
        }

        @Override
        // Occurs when the device has trouble scanning your finger (sensor is dirty, not scanning the entire finger, etc)
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            Toast.makeText(MainActivity.this, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show();
        }

        @Override
        // Occurs when a fingerprint has been scanned and is recognized
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            Toast.makeText(MainActivity.this, "Success!", Toast.LENGTH_LONG).show();
        }

        @Override
        //Occurs when an error occurs during the process of scanning your finger
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            Toast.makeText(MainActivity.this, "Authentication error\n" + errString, Toast.LENGTH_LONG).show();
        }

    }


}
