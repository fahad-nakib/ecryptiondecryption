package ecryptiondecryption;

import java.awt.Frame;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class source extends javax.swing.JFrame {

    /**
     * Creates new form EncryptDecrypt
     */
    private static SecretKeySpec secretKey;
    private static byte[] key;
    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
    public source() {
        initComponents();
    }


    @SuppressWarnings("unchecked")
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        text1 = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        text2 = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        text3 = new javax.swing.JTextArea();
        jScrollPane4 = new javax.swing.JScrollPane();
        text4 = new javax.swing.JTextArea();
        msg1 = new javax.swing.JTextField();
        msg2 = new javax.swing.JTextField();
        encrypt = new javax.swing.JButton();
        decrypt = new javax.swing.JButton();
        copyencrypt = new javax.swing.JButton();
        copydecrypt = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        message1 = new javax.swing.JLabel();
        message2 = new javax.swing.JLabel();
        mainsection = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Encryption and Decryption ");
        setAlwaysOnTop(true);
        setUndecorated(true);
        setResizable(false);
        getContentPane().setLayout(null);

        text1.setBackground(new java.awt.Color(255, 255, 255));
        text1.setColumns(20);
        text1.setFont(new java.awt.Font("Dialog", 0, 14));
        text1.setForeground(new java.awt.Color(0, 0, 0));
        text1.setRows(5);
        text1.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102), 2));
        jScrollPane1.setViewportView(text1);

        getContentPane().add(jScrollPane1);
        jScrollPane1.setBounds(80, 80, 300, 120);

        text2.setBackground(new java.awt.Color(255, 255, 255));
        text2.setColumns(20);
        text2.setFont(new java.awt.Font("Dialog", 0, 14));
        text2.setForeground(new java.awt.Color(0, 0, 0));
        text2.setRows(5);
        text2.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102), 2));
        jScrollPane2.setViewportView(text2);

        getContentPane().add(jScrollPane2);
        jScrollPane2.setBounds(80, 322, 300, 120);

        text3.setBackground(new java.awt.Color(255, 255, 255));
        text3.setColumns(20);
        text3.setFont(new java.awt.Font("Dialog", 0, 14));
        text3.setForeground(new java.awt.Color(0, 0, 0));
        text3.setRows(5);
        text3.setToolTipText("");
        text3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102), 2));
        jScrollPane3.setViewportView(text3);

        getContentPane().add(jScrollPane3);
        jScrollPane3.setBounds(470, 80, 320, 120);

        text4.setBackground(new java.awt.Color(255, 255, 255));
        text4.setColumns(20);
        text4.setFont(new java.awt.Font("Dialog", 0, 14));
        text4.setForeground(new java.awt.Color(0, 0, 0));
        text4.setRows(5);
        text4.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102), 2));
        jScrollPane4.setViewportView(text4);

        getContentPane().add(jScrollPane4);
        jScrollPane4.setBounds(470, 320, 320, 120);

        msg1.setBackground(new java.awt.Color(255, 255, 255));
        msg1.setForeground(new java.awt.Color(0, 0, 0));
        msg1.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        getContentPane().add(msg1);
        msg1.setBounds(200, 220, 180, 30);

        msg2.setBackground(new java.awt.Color(255, 255, 255));
        msg2.setForeground(new java.awt.Color(0, 0, 0));
        msg2.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        getContentPane().add(msg2);
        msg2.setBounds(595, 220, 190, 30);

        encrypt.setBackground(new java.awt.Color(0, 51, 51));
        encrypt.setFont(new java.awt.Font("Dialog", 1, 14));
        encrypt.setForeground(new java.awt.Color(255, 255, 255));
        encrypt.setText("Encrypt");
        encrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encrypt(evt);
            }
        });
        getContentPane().add(encrypt);
        encrypt.setBounds(80, 275, 90, 30);

        decrypt.setBackground(new java.awt.Color(0, 51, 51));
        decrypt.setFont(new java.awt.Font("Dialog", 1, 14));
        decrypt.setForeground(new java.awt.Color(255, 255, 255));
        decrypt.setText("Decrypt");
        decrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decrypt(evt);
            }
        });
        getContentPane().add(decrypt);
        decrypt.setBounds(470, 275, 90, 30);

        copyencrypt.setBackground(new java.awt.Color(102, 0, 0));
        copyencrypt.setFont(new java.awt.Font("Dialog", 1, 12));
        copyencrypt.setForeground(new java.awt.Color(255, 255, 255));
        copyencrypt.setText("Copy Encryption");
        copyencrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyencryptActionPerformed(evt);
            }
        });
        getContentPane().add(copyencrypt);
        copyencrypt.setBounds(240, 275, 140, 30);

        copydecrypt.setBackground(new java.awt.Color(102, 0, 0));
        copydecrypt.setFont(new java.awt.Font("Dialog", 1, 12));
        copydecrypt.setForeground(new java.awt.Color(255, 255, 255));
        copydecrypt.setText("Copy Decryption");
        copydecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copydecryptActionPerformed(evt);
            }
        });
        getContentPane().add(copydecrypt);
        copydecrypt.setBounds(633, 275, 150, 30);

        jLabel2.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        jLabel2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel2MousePressed(evt);
            }
        });
        getContentPane().add(jLabel2);
        jLabel2.setBounds(810, 5, 30, 20);

        jLabel3.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        jLabel3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel3MousePressed(evt);
            }
        });
        getContentPane().add(jLabel3);
        jLabel3.setBounds(780, 5, 30, 20);

        jLabel1.setFont(new java.awt.Font("Dialog", 1, 14));
        jLabel1.setForeground(new java.awt.Color(204, 51, 0));
        jLabel1.setText("Encryption Key");
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102)));
        getContentPane().add(jLabel1);
        jLabel1.setBounds(80, 220, 120, 30);

        jLabel4.setFont(new java.awt.Font("Dialog", 1, 14));
        jLabel4.setForeground(new java.awt.Color(204, 51, 0));
        jLabel4.setText("Decryption Key");
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(102, 102, 102)));
        getContentPane().add(jLabel4);
        jLabel4.setBounds(470, 220, 120, 30);

        jLabel5.setFont(new java.awt.Font("Dialog", 1, 18));
        jLabel5.setForeground(new java.awt.Color(0, 0, 51));
        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Message to Decrypt");
        getContentPane().add(jLabel5);
        jLabel5.setBounds(470, 50, 300, 30);

        jLabel6.setFont(new java.awt.Font("Dialog", 1, 18));
        jLabel6.setForeground(new java.awt.Color(0, 0, 51));
        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel6.setText("Message to Encrypt ");
        getContentPane().add(jLabel6);
        jLabel6.setBounds(80, 50, 300, 30);

        message1.setForeground(new java.awt.Color(204, 0, 0));
        message1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        getContentPane().add(message1);
        message1.setBounds(80, 450, 300, 20);

        message2.setForeground(new java.awt.Color(204, 0, 0));
        message2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        getContentPane().add(message2);
        message2.setBounds(470, 450, 320, 20);

        mainsection.setForeground(new java.awt.Color(153, 0, 0));
        mainsection.setIcon(new javax.swing.ImageIcon(getClass().getResource("/image/edcrypt.png")));
        mainsection.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        getContentPane().add(mainsection);
        mainsection.setBounds(0, 0, 850, 500);

        setSize(new java.awt.Dimension(850, 499));
        setLocationRelativeTo(null);
    }

    private void jLabel2MousePressed(java.awt.event.MouseEvent evt) {

        System.exit(0);

    }

    private void jLabel3MousePressed(java.awt.event.MouseEvent evt) {

        this.setState(Frame.ICONIFIED);
    }

private static final int Nb = 4; // Number of columns (32-bit words) comprising the State.
    private static final int Nk = 4; // Number of 32-bit words in the key.
    private static final int Nr = 10; // Number of rounds.

    private static final byte[] sBox = {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
            (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
            (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
            (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
            (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
            (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
            (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
            (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
            (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
            (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
            (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16,

    };

    private static final byte[] rCon = {
            (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80,
            (byte) 0x1b, (byte) 0x36
    };

    private static final byte[][] mixColumnsMatrix = {
            {(byte) 0x02, (byte) 0x03, 0x01, 0x01},
            {0x01, (byte) 0x02, (byte) 0x03, 0x01},
            {0x01, 0x01, (byte) 0x02, (byte) 0x03},
            {(byte) 0x03, 0x01, 0x01, (byte) 0x02}
    };

    private static byte[] encrypt(byte[] input, byte[] key) {
        byte[][] state = new byte[4][Nb];
        // Initialize state array from the input
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = input[i * 4 + j];
            }
        }

        // Key expansion
        byte[][] roundKeys = keyExpansion(key);

        // AddRoundKey
        addRoundKey(state, roundKeys, 0);

        // Main rounds
        for (int round = 1; round < Nr; round++) {
            byteSubstitution(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys, round);
        }

        // Final round
        byteSubstitution(state);
        shiftRows(state);
        addRoundKey(state, roundKeys, Nr);

        // Convert state back to array
        byte[] output = new byte[16];
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = state[j][i];
            }
        }

        return output;
    }




    private void copyencryptActionPerformed(java.awt.event.ActionEvent evt) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text2.getText()),null);
        message1.setText("Your encryption result is copied!");
        message2.setText("");
    }


    private static byte[] decrypt(byte[] input, byte[] key) {
        byte[][] state = new byte[4][Nb];
        // Initialize state array from the input
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = input[i * 4 + j];
            }
        }

        // Key expansion
        byte[][] roundKeys = keyExpansion(key);

        // Initial round
        addRoundKey(state, roundKeys, Nr);

        // Main rounds
        for (int round = Nr - 1; round > 0; round--) {
            invShiftRows(state);
            invByteSubstitution(state);
            addRoundKey(state, roundKeys, round);
            invMixColumns(state);
        }

        // Final round
        invShiftRows(state);
        invByteSubstitution(state);
        addRoundKey(state, roundKeys, 0);

        // Convert state back to array
        byte[] output = new byte[16];
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = state[j][i];
            }
        }

        return output;
    }

    private static void addRoundKey(byte[][] state, byte[][] roundKeys, int round) {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = (byte) (state[j][i] ^ roundKeys[round][i * 4 + j]);
            }
        }
    }

    private static void byteSubstitution(byte[][] state) {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = sBox[state[j][i] & 0xFF];
            }
        }
    }

    private static void invByteSubstitution(byte[][] state) {
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 256; k++) {
                    if (sBox[k] == state[j][i]) {
                        state[j][i] = (byte) k;
                        break;
                    }
                }
            }
        }
    }

    private static void shiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            byte[] temp = new byte[4];
            System.arraycopy(state[i], 0, temp, 0, 4);
            System.arraycopy(temp, 4 - i, state[i], 0, i);
            System.arraycopy(temp, 0, state[i], i, 4 - i);
        }
    }

    private static void invShiftRows(byte[][] state) {
        for (int i = 1; i < 4; i++) {
            byte[] temp = new byte[4];
            System.arraycopy(state[i], 0, temp, 0, 4);
            System.arraycopy(temp, i, state[i], 0, 4 - i);
            System.arraycopy(temp, 0, state[i], 4 - i, i);
        }
    }

    private static void mixColumns(byte[][] state) {
        for (int i = 0; i < Nb; i++) {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++) {
                temp[j] = (byte) (mixColumnsMatrix[j][0] * state[0][i] +
                        mixColumnsMatrix[j][1] * state[1][i] +
                        mixColumnsMatrix[j][2] * state[2][i] +
                        mixColumnsMatrix[j][3] * state[3][i]);
            }
            System.arraycopy(temp, 0, state[0], i, 4);
        }
    }

    private static void invMixColumns(byte[][] state) {
        for (int i = 0; i < Nb; i++) {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++) {
                temp[j] = (byte) ((byte) 0x0e * state[0][i] +
                        (byte) 0x0b * state[1][i] +
                        (byte) 0x0d * state[2][i] +
                        (byte) 0x09 * state[3][i]);
            }
            System.arraycopy(temp, 0, state[0], i, 4);
        }
    }

    private static byte[][] keyExpansion(byte[] key) {
        byte[][] roundKeys = new byte[Nb * (Nr + 1)][4];
        System.arraycopy(key, 0, roundKeys[0], 0, 16);

        for (int i = 1; i < Nr + 1; i++) {
            byte[] temp = new byte[4];
            System.arraycopy(roundKeys[(i - 1) * Nb], 12, temp, 0, 4);
            temp = shiftRows(temp);
            temp = subBytes(temp);
            temp = addRoundConstant(temp, i);
            System.arraycopy(temp, 0, roundKeys[i * Nb], 0, 4);

            for (int j = 1; j < Nb; j++) {
                System.arraycopy(roundKeys[(i - 1) * Nb + j], 0, temp, 0, 4);
                for (int k = 0; k < 4; k++) {
                    roundKeys[i * Nb + j][k] = (byte) (roundKeys[i * Nb + j - 1][k] ^ temp[k]);
                }
            }
        }

        return roundKeys;
    }

    private static byte[] shiftRows(byte[] input) {
        byte[] output = new byte[4];
        System.arraycopy(input, 1, output, 0, 3);
        output[3] = input[0];
        return output;
    }

    private static byte[] subBytes(byte[] input) {
        for (int i = 0; i < 4; i++) {
            input[i] = sBox[input[i] & 0xFF];
        }
        return input;
    }

    private static byte[] addRoundConstant(byte[] input, int round) {
        input[0] = (byte) (input[0] ^ rCon[round - 1]);
        return input;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void copydecryptActionPerformed(java.awt.event.ActionEvent evt) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text4.getText()),null);
        message2.setText("Your decryption result is copied!");
        message1.setText("");
    }


    public static void main(String args[]) {

        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(source.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(source.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(source.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(source.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new source().setVisible(true);
            }
        });
    }

    private javax.swing.JButton copydecrypt;
    private javax.swing.JButton copyencrypt;
    private javax.swing.JButton decrypt;
    private javax.swing.JButton encrypt;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JLabel mainsection;
    private javax.swing.JLabel message1;
    private javax.swing.JLabel message2;
    private javax.swing.JTextField msg1;
    private javax.swing.JTextField msg2;
    private javax.swing.JTextArea text1;
    private javax.swing.JTextArea text2;
    private javax.swing.JTextArea text3;
    private javax.swing.JTextArea text4;

}
