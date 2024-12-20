import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class PasswordManager {

    private static final String MASTER_KEY = "MasterKey1234567"; // Главный ключ для шифрования ключей
    private static final String SALT = "RandomSalt1234";     // Соль для подсаливания

    private static Map<String, Map<String, String>> userDatabase = new HashMap<>(); // База данных пользователей
    private static Map<String, String> encryptedKeys = new HashMap<>(); // Хранилище зашифрованных ключей
    private static Map<String, List<String>> passwordStorage = new HashMap<>(); // Хранилище паролей пользователей

    // Регистрация пользователя
    public static void registerUser(String username, String password) {
        if (userDatabase.containsKey(username)) {
            System.out.println("User already exists. Please log in.");
            return;
        }

        Map<String, String> userDetails = new HashMap<>();
        userDetails.put("password", password); // Храним пароль в открытом виде
        userDatabase.put(username, userDetails);
        passwordStorage.put(username, new ArrayList<>());

        System.out.println("User registered successfully!");
    }

    public static boolean authenticateUser(String username, String password) {
        Map<String, String> userDetails = userDatabase.get(username);
        if (userDetails == null) {
            System.out.println("User not registered. Please register first.");
            return false;
        }

        String storedPassword = userDetails.get("password");
        return storedPassword.equals(password);
    }

    public static void saveUserPassword(String username, String passwordName, String passwordValue, String encryptionMethod) {
        try {
            List<String> passwords = passwordStorage.get(username);
            if (passwords != null) {
                String encryptedPassword = encryptPassword(passwordValue, encryptionMethod);
                passwords.add(passwordName + " : " + encryptedPassword);
                System.out.println("Password saved successfully!");
            } else {
                System.out.println("Error: User does not exist.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("An unexpected error occurred while saving the password.");
        }
    }

    public static void displayUserPasswords(String username) {
        List<String> passwords = passwordStorage.get(username);
        if (passwords == null || passwords.isEmpty()) {
            System.out.println("No saved passwords.");
        } else {
            System.out.println("--- Stored Passwords ---");
            for (String entry : passwords) {
                System.out.println(entry);
            }
        }
    }

    // Шифрование паролей
    private static String encryptPassword(String password, String method) {
        switch (method.toLowerCase()) {
            case "plain":
                return password;
            case "base64":
                return encryptBase64(password);
            case "md5":
                return encryptMD5(password);
            case "feistel":
                return encryptFeistel(password);
            case "salted":
                return encryptSalted(password);
            default:
                throw new IllegalArgumentException("Unsupported encryption method: " + method);
        }
    }

    // Base64 шифрование
    public static String encryptBase64(String password) {
        return Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));
    }

    // MD5 шифрование
    public static String encryptMD5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing MD5", e);
        }
    }

    // Шифр Фейстеля (с использованием AES для упрощения)
    public static String encryptFeistel(String password) {
        try {
            String key = getDecryptedKey("AES_KEY");
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Error with Feistel encryption", e);
        }
    }

    // Подсаливание пароля
    public static String encryptSalted(String password) {
        return encryptMD5(password + SALT);
    }

    // --- Зашифрованное хранилище ключей ---

    public static void storeEncryptedKey(String keyName, String keyValue) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec masterKeySpec = new SecretKeySpec(MASTER_KEY.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, masterKeySpec);
            byte[] encryptedKey = cipher.doFinal(keyValue.getBytes(StandardCharsets.UTF_8));
            encryptedKeys.put(keyName, Base64.getEncoder().encodeToString(encryptedKey));
        } catch (Exception e) {
            throw new RuntimeException("Error storing encrypted key", e);
        }
    }

    public static String getDecryptedKey(String keyName) {
        try {
            String encryptedKey = encryptedKeys.get(keyName);
            if (encryptedKey == null) throw new RuntimeException("Key not found: " + keyName);

            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec masterKeySpec = new SecretKeySpec(MASTER_KEY.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, masterKeySpec);
            byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
            return new String(decryptedKey, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting key", e);
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        storeEncryptedKey("AES_KEY", "SuperSecretKey12");
        String currentUser = null;

        while (true) {
            try {
                System.out.println("\n--- Password Manager ---");
                System.out.println("1. Register User");
                System.out.println("2. Authenticate User");
                System.out.println("3. Save Password");
                System.out.println("4. View Saved Passwords");
                System.out.println("5. Exit");
                System.out.print("Enter your choice: ");

                if (!scanner.hasNextInt()) {
                    System.out.println("Error: Invalid input. Please enter a number between 1 and 5.");
                    scanner.nextLine();
                    continue;
                }

                int choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1) {
                    System.out.print("Enter username: ");
                    String username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();
                    registerUser(username, password);

                } else if (choice == 2) {
                    System.out.print("Enter username: ");
                    String username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();

                    if (authenticateUser(username, password)) {
                        System.out.println("Authentication successful!");
                        currentUser = username;
                    } else {
                        System.out.println("Authentication failed!");
                    }

                } else if (choice == 3) {
                    if (currentUser == null) {
                        System.out.println("Please authenticate first.");
                        continue;
                    }
                    System.out.print("Enter password name (e.g., Email, Bank): ");
                    String passwordName = scanner.nextLine();
                    System.out.print("Enter password value: ");
                    String passwordValue = scanner.nextLine();
                    System.out.print("Enter encryption method (plain, base64, md5, feistel, salted): ");
                    String encryptionMethod = scanner.nextLine();
                    saveUserPassword(currentUser, passwordName, passwordValue, encryptionMethod);

                } else if (choice == 4) {
                    if (currentUser == null) {
                        System.out.println("Please authenticate first.");
                        continue;
                    }
                    displayUserPasswords(currentUser);

                } else if (choice == 5) {
                    System.out.println("Exiting Password Manager. Goodbye!");
                    break;
                } else {
                    System.out.println("Invalid choice. Please enter a number between 1 and 5.");
                }
            } catch (Exception e) {
                System.out.println("Error: Invalid input. Please try again.");
                scanner.nextLine(); // Очистка ввода
            }
        }
    }
}
