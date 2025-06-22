import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Image;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

public class ImageEncryptionApp {

    private static final int HEADER_LENGTH = 128; // Fixed length for header message
    private static final String HEADER_MESSAGE = "This file is encrypted. Use ImageEncryptionApp to decrypt it.";

    private static JLabel selectedImageLabel;
    private static BufferedImage originalImage;
    private static File originalFile; // Store the original file path
    private static String originalExtension; // Store the original file extension

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Image Encryption App");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setLayout(new BorderLayout());
            frame.getContentPane().setBackground(Color.BLACK);

            JPanel headingPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
            headingPanel.setBackground(Color.BLACK);
            JLabel headingLabel = new JLabel("Image Encryption");
            headingLabel.setFont(new Font("Arial", Font.BOLD, 40));
            headingLabel.setForeground(Color.WHITE);
            headingPanel.add(headingLabel);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
            buttonPanel.setBackground(Color.BLACK);

            selectedImageLabel = new JLabel();
            selectedImageLabel.setHorizontalAlignment(JLabel.CENTER);
            selectedImageLabel.setForeground(Color.WHITE);

            JButton browseButton = new JButton("Browse");
            JButton encryptButton = new JButton("Encrypt");
            JButton decryptButton = new JButton("Decrypt");
            JButton exitButton = new JButton("Exit");

            Color yellowButtonColor = new Color(255, 215, 0);
            browseButton.setBackground(yellowButtonColor);
            encryptButton.setBackground(yellowButtonColor);
            decryptButton.setBackground(yellowButtonColor);
            exitButton.setBackground(yellowButtonColor);

            Color blackTextColor = Color.BLACK;
            browseButton.setForeground(blackTextColor);
            encryptButton.setForeground(blackTextColor);
            decryptButton.setForeground(blackTextColor);
            exitButton.setForeground(blackTextColor);

            Dimension buttonSize = new Dimension(120, 40);
            browseButton.setPreferredSize(buttonSize);
            encryptButton.setPreferredSize(buttonSize);
            decryptButton.setPreferredSize(buttonSize);
            exitButton.setPreferredSize(buttonSize);

            JPasswordField passwordField = new JPasswordField(10);
            setPlaceholder(passwordField, "Enter Password");

            browseButton.addActionListener(e -> {
                JFileChooser fileChooser = new JFileChooser();
                // Add file filter for image formats
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                    "Image Files", "jpg", "jpeg", "png");
                fileChooser.setFileFilter(filter);
                fileChooser.showOpenDialog(null);
                File selectedFile = fileChooser.getSelectedFile();
                if (selectedFile != null) {
                    originalFile = selectedFile;
                    // Check if the file is encrypted
                    if (isEncryptedFile(selectedFile)) {
                        originalImage = null;
                        selectedImageLabel.setIcon(null);
                        selectedImageLabel.setText("Encrypted file selected: " + selectedFile.getName());
                        // Extract extension (remove .jpg, .png, etc.)
                        String fileName = selectedFile.getName();
                        originalExtension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                    } else {
                        originalImage = loadImage(selectedFile);
                        if (originalImage != null) {
                            displayImage(originalImage, selectedImageLabel, frame);
                            selectedImageLabel.setText("");
                            // Store the file extension
                            String fileName = selectedFile.getName();
                            originalExtension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                        }
                    }
                }
            });

            encryptButton.addActionListener(e -> {
                if (isPasswordEntered(passwordField)) {
                    if (originalImage != null && originalFile != null) {
                        try {
                            String password = new String(passwordField.getPassword());
                            byte[] encryptedData = encryptImage(originalImage, password);
                            // Overwrite the original file with encrypted data
                            saveEncryptedImage(encryptedData, originalFile);
                            // Clear the image preview
                            selectedImageLabel.setIcon(null);
                            selectedImageLabel.setText("");
                            JOptionPane.showMessageDialog(null, "Image encrypted successfully and overwritten as " + originalFile.getName() + ". Original image is no longer accessible.");
                            passwordField.setText("");
                            originalImage = null; // Clear original image from memory
                        } catch (Exception ex) {
                            JOptionPane.showMessageDialog(null, "Encryption failed: " + ex.getMessage());
                        }
                    } else {
                        JOptionPane.showMessageDialog(null, "Please select a valid image first");
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Please enter a password");
                }
            });

            decryptButton.addActionListener(e -> {
                if (isPasswordEntered(passwordField)) {
                    if (originalFile != null && originalFile.exists()) {
                        try {
                            String password = new String(passwordField.getPassword());
                            byte[] encryptedData = readEncryptedFile(originalFile);
                            BufferedImage decryptedImage = decryptImage(encryptedData, password);
                            displayImage(decryptedImage, selectedImageLabel, frame);
                            // Overwrite the file with decrypted image
                            saveImage(decryptedImage, originalFile, originalExtension);
                            JOptionPane.showMessageDialog(null, "Image decrypted and saved as " + originalFile.getName());
                            passwordField.setText("");
                            originalImage = decryptedImage;
                        } catch (Exception ex) {
                            JOptionPane.showMessageDialog(null, "Decryption failed: " + ex.getMessage());
                        }
                    } else {
                        JOptionPane.showMessageDialog(null, "No file selected. Please select an encrypted file");
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Please enter a password");
                }
            });

            exitButton.addActionListener(e -> System.exit(0));

            frame.add(headingPanel, BorderLayout.NORTH);
            frame.add(selectedImageLabel, BorderLayout.CENTER);
            buttonPanel.add(browseButton);
            buttonPanel.add(encryptButton);
            buttonPanel.add(decryptButton);
            buttonPanel.add(exitButton);
            buttonPanel.add(passwordField);
            frame.add(buttonPanel, BorderLayout.SOUTH);

            frame.setSize(800, 600);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }

    private static boolean isEncryptedFile(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[HEADER_LENGTH];
            int bytesRead = fis.read(header);
            if (bytesRead != HEADER_LENGTH) {
                return false;
            }
            String headerStr = new String(header, "ASCII").trim();
            return headerStr.startsWith(HEADER_MESSAGE);
        } catch (IOException e) {
            return false;
        }
    }

    private static BufferedImage loadImage(File file) {
        try {
            BufferedImage image = ImageIO.read(file);
            if (image == null) {
                throw new IOException("Unsupported image format");
            }
            return image;
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Failed to load image: " + e.getMessage());
            return null;
        }
    }

    private static void displayImage(BufferedImage image, JLabel label, JFrame frame) {
        int screenWidth = frame.getWidth();
        int screenHeight = frame.getHeight();
        int displayWidth = (int) (screenWidth * 0.25);
        int displayHeight = (int) (screenHeight * 0.25);

        Image scaledImage = image.getScaledInstance(displayWidth, displayHeight, Image.SCALE_SMOOTH);
        ImageIcon imageIcon = new ImageIcon(scaledImage);
        label.setIcon(imageIcon);
    }

    private static void setPlaceholder(JPasswordField passwordField, String placeholder) {
        passwordField.setEchoChar((char) 0);
        passwordField.setText(placeholder);

        passwordField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (String.valueOf(passwordField.getPassword()).equals(placeholder)) {
                    passwordField.setEchoChar('*');
                    passwordField.setText("");
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (String.valueOf(passwordField.getPassword()).isEmpty()) {
                    passwordField.setEchoChar((char) 0);
                    passwordField.setText(placeholder);
                }
            }
        });
    }

    private static boolean isPasswordEntered(JPasswordField passwordField) {
        String enteredPassword = String.valueOf(passwordField.getPassword());
        return enteredPassword != null && !enteredPassword.trim().isEmpty() && !enteredPassword.equals("Enter Password");
    }

    private static byte[] encryptImage(BufferedImage image, String password) throws Exception {
        // Convert image to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos); // Use PNG as intermediate format
        byte[] imageBytes = baos.toByteArray();

        // Generate AES key from password using PBKDF2
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKey secretKey = deriveKeyFromPassword(password, salt);

        // Initialize AES cipher in encryption mode
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Encrypt the image bytes
        byte[] encryptedBytes = cipher.doFinal(imageBytes);

        // Create header
        byte[] headerBytes = new byte[HEADER_LENGTH];
        byte[] messageBytes = HEADER_MESSAGE.getBytes("ASCII");
        System.arraycopy(messageBytes, 0, headerBytes, 0, Math.min(messageBytes.length, HEADER_LENGTH));
        // Pad remaining header with spaces
        for (int i = messageBytes.length; i < HEADER_LENGTH; i++) {
            headerBytes[i] = ' ';
        }

        // Combine header, IV, salt, and encrypted data
        byte[] result = new byte[headerBytes.length + iv.length + salt.length + encryptedBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(iv, 0, result, headerBytes.length, iv.length);
        System.arraycopy(salt, 0, result, headerBytes.length + iv.length, salt.length);
        System.arraycopy(encryptedBytes, 0, result, headerBytes.length + iv.length + salt.length, encryptedBytes.length);

        return result;
    }

    private static BufferedImage decryptImage(byte[] encryptedData, String password) throws Exception {
        // Check if encrypted data is long enough
        if (encryptedData.length < HEADER_LENGTH + 32) {
            throw new Exception("Invalid encrypted file format");
        }

        // Skip header (first 128 bytes)
        byte[] iv = new byte[16];
        byte[] salt = new byte[16];
        byte[] encryptedBytes = new byte[encryptedData.length - HEADER_LENGTH - 16 - 16];
        System.arraycopy(encryptedData, HEADER_LENGTH, iv, 0, 16);
        System.arraycopy(encryptedData, HEADER_LENGTH + 16, salt, 0, 16);
        System.arraycopy(encryptedData, HEADER_LENGTH + 32, encryptedBytes, 0, encryptedBytes.length);

        // Generate AES key from password and salt using PBKDF2
        SecretKey secretKey = deriveKeyFromPassword(password, salt);

        // Initialize AES cipher in decryption mode
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the image bytes
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Convert decrypted bytes back to BufferedImage
        ByteArrayInputStream bais = new ByteArrayInputStream(decryptedBytes);
        BufferedImage image = ImageIO.read(bais);
        if (image == null) {
            throw new Exception("Failed to decode decrypted image");
        }
        return image;
    }

    private static SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        // Use PBKDF2 to derive a 256-bit AES key from the password
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 10000, 256); // 10,000 iterations
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void saveEncryptedImage(byte[] encryptedData, File outputFile) {
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(encryptedData);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Failed to save encrypted image: " + e.getMessage());
        }
    }

    private static byte[] readEncryptedFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        }
    }

    private static void saveImage(BufferedImage image, File outputFile, String format) {
        try {
            ImageIO.write(image, format, outputFile);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Failed to save image: " + e.getMessage());
        }
    }
}
