/**
 * XIVOTPGenerator is a Java class that generates One-Time Passwords (OTP) for XIVLauncher
 * based on a user-provided secret key. It also launches XIVLauncher and simulates typing
 * the generated OTP into it.
 *
 * @author isrever
 * @version 1.0.0
 * @since 17-12-2023
 */

import java.awt.AWTException;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.io.*;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class XIVOTPGenerator {
    /**
     * The main method of the XIVOTPGenerator class. This method serves as the entry point
     * for the OTP generation and XIVLauncher automation process.
     *
     * It performs the following tasks:
     * 1. Loads the OTP secret key from the configuration file.
     * 2. Launches the XIVLauncher executable.
     * 3. Generates a One-Time Password (OTP) based on the loaded secret key.
     * 4. Simulates typing the OTP into the active window (XIVLauncher).
     *
     * @param args The command-line arguments (not used in this program).
     */
    private static String SECRET;
    private static final String LAUNCHER_PATH = System.getProperty("user.home") + "\\AppData\\Local\\XIVLauncher\\XIVLauncher.exe";
    public static void main(String[] args) {
        loadConfig();
        System.out.println(LAUNCHER_PATH);

        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                launchLauncher();
            }
        }, 0);

        Timer timer2 = new Timer();
        timer2.schedule(new TimerTask() {
            @Override
            public void run() {
                String OTP = generateOTP(SECRET, 6, 30);
                simulateTyping(OTP);
            }
        }, 2000);
    }

    /**
     * Loads the OTP secret key from the configuration file.
     * If the configuration file does not exist, it creates one with a default secret.
     * Exits the program if a valid secret is not found.
     */
    private static void loadConfig() {
        File configFile = new File("otp_config.cfg");

        if (!configFile.exists()) {
            createConfigFile(configFile);
        }

        try {
            // Read the .cfg file
            FileReader reader = new FileReader(configFile);
            Properties properties = new Properties();
            properties.load(reader);

            SECRET = properties.getProperty("SECRET");

            reader.close();

            if (SECRET == null || SECRET.isEmpty() || SECRET.equals("SECRETHERE")) {
                System.err.println("SECRET MISSING: Please add a valid secret to otp_config.cfg");
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Error reading the config file: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Creates a configuration file with a default secret.
     *
     * @param configFile The file to create.
     */
    private static void createConfigFile(File configFile) {
        try {
            Properties properties = new Properties();
            properties.setProperty("SECRET", "SECRETHERE"); // You can set a default value

            FileWriter writer = new FileWriter(configFile);
            properties.store(writer, "OTP Configuration");
            writer.close();

            System.out.println("otp_config.cfg created with default SECRET value. Please edit the file and replace 'SECRETHERE' with your actual secret.");
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error creating the config file: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Launches the XIVLauncher executable.
     */
    private static void launchLauncher() {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("\"" + LAUNCHER_PATH + "\"");
            Process process = processBuilder.start();

            process.waitFor();
        } catch (IOException | InterruptedException e) {
            System.err.println("Error launching the launcher: " + e.getMessage());
        }
    }

    /**
     * Simulates typing the provided text into the active window.
     *
     * @param text The text to be typed.
     */
    private static void simulateTyping(String text) {
        try {
            Robot robot = new Robot();
            StringSelection selection = new StringSelection(text);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);

            robot.keyPress(KeyEvent.VK_CONTROL);
            robot.keyPress(KeyEvent.VK_V);
            robot.keyRelease(KeyEvent.VK_V);
            robot.keyRelease(KeyEvent.VK_CONTROL);

            robot.keyPress(KeyEvent.VK_ENTER);
            robot.keyRelease(KeyEvent.VK_ENTER);

            System.exit(0);
        } catch (AWTException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a One-Time Password (OTP) based on a secret key, length, and a time window.
     *
     * @param secret The secret key for OTP generation.
     * @param length The length of the OTP.
     * @param window The time window for OTP validity.
     * @return The generated OTP as a String or null in case of an exception.
     */
    private static String generateOTP(String secret, int length, int window) {
        String base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        byte[] secretBytes = base32ToBytes(secret);
        long time = System.currentTimeMillis() / 1000 / window;
        byte[] timeBytes = longToByteArray(time);

        try {
            Mac hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(secretBytes, "RAW");
            hmac.init(keySpec);
            byte[] hash = hmac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0xf;
            long truncatedHash = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

            long modNumber = (long) Math.pow(10, length);
            long otp = truncatedHash % modNumber;

            return String.format("%0" + length + "d", otp);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Converts a base32 encoded string to a byte array.
     *
     * @param base32 The base32 encoded string.
     * @return The byte array representation of the base32 string.
     */
    public static byte[] base32ToBytes(String base32) {
        String base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder bits = new StringBuilder();
        for (char c : base32.toCharArray()) {
            int val = base32chars.indexOf(c);
            bits.append(String.format("%5s", Integer.toBinaryString(val)).replace(' ', '0'));
        }

        StringBuilder hex = new StringBuilder();
        int i = 0;
        while (i + 4 <= bits.length()) {
            int chunk = Integer.parseInt(bits.substring(i, i + 4), 2);
            hex.append(Integer.toHexString(chunk));
            i += 4;
        }

        return hexToBytes(hex.toString());
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex The hexadecimal string.
     * @return The byte array representation of the hexadecimal string.
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }

        return data;
    }

    /**
     * Converts a long value to a byte array.
     *
     * @param value The long value to be converted.
     * @return The byte array representation of the long value.
     */
    private static byte[] longToByteArray(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }
}
