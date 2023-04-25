import javax.swing.JOptionPane;
import java.awt.HeadlessException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class EnrolmentAndVerification {

    static String[] breachedPasswords;
    static String[] profanityFilter;
    public static void main(String[] args) throws HeadlessException, NoSuchAlgorithmException {

        Connection connection = null;
        try
        {
        // create a database connection
        connection = DriverManager.getConnection("jdbc:sqlite:sample.db");
        Statement statement = connection.createStatement();
        statement.setQueryTimeout(30);  // set timeout to 30 sec.

        statement.executeUpdate("drop table if exists person");
        statement.executeUpdate("create table person (username string,salt string,hashpwd string)");

            // breached passwords list
            ArrayList<String> passwordList = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new FileReader("breachedpasswords.txt"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    passwordList.add(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            breachedPasswords = passwordList.toArray(new String[0]);

            //profanity usernames
            ArrayList<String> profanityList = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new FileReader("profanity.txt"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    profanityList.add(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            profanityFilter = profanityList.toArray(new String[0]);

            String[] buttons = { "Enrol", "Log On", "Exit"};    

            //change this to LoggedOn boolean variable, to keep track of status
            while(true){
                int returnValue = JOptionPane.showOptionDialog(null, "What Would You Like To Do?", "EnrolmentAndVerification",
                JOptionPane.WARNING_MESSAGE, 0, null, buttons, buttons[0]);

                // EXIT BUTTON OR X BUTTON
                if(returnValue == -1 || returnValue == 2){
                    System.exit(0);            
                }
                // ENROLMENT ---------------------------------------------------------------------------------------------------
                else if(returnValue == 0){
                    // Enrolment phase
                    String username = promptUsername();
                    while (!isValidUsername(username)) {
                        username = promptUsername();
                    }
                    String password = promptPassword();
                    while (!isValidPassword(password)) {
                        password = promptPassword();
                    }
                    // storeUserData(username, salt, hashpwd);
                    String[] hash = hashPassword(password, null);
                    String sql = "insert into person values('" + username.toLowerCase() + "','" + hash[1] + "','" + hash[0] + "');";
                    statement.executeUpdate(sql);

                    //log in now notification
                    JOptionPane.showMessageDialog(null, "Awesome! Thank you for enrolling, you can now log in");
                }
                // VERIFICATION ---------------------------------------------------------------------------------------------------
                else if(returnValue == 1){
                    Boolean logon = false;
                    // Verification phase
                    String inputUsername = JOptionPane.showInputDialog("Enter your username:");

                    // check username exists
                    ResultSet rs = statement.executeQuery("select * from person where username = '" + inputUsername.toLowerCase() + "';");
                    //System.out.println("name = " + rs.getString("username"));

                    if(rs.getString("username") != null){
                        String inputPassword = JOptionPane.showInputDialog("Enter your password:");
                        rs = statement.executeQuery("select * from person where username = '" + inputUsername.toLowerCase() + "';");
                        String salt = rs.getString("salt");

                        String rehashedInputPassword[] = hashPassword(inputPassword, salt);
                        System.out.println("sotred passwrod: " + rs.getString("hashpwd") + " rehashed: " + rehashedInputPassword[0]);

                        if (rehashedInputPassword[0].equals(rs.getString("hashpwd"))) {
                            JOptionPane.showMessageDialog(null, "Welcome, " + inputUsername + "!");
                            JOptionPane.showMessageDialog(null, "Please Log Out");
                        }else{
                            JOptionPane.showMessageDialog(null, "Incorrect password.");
                        }
                    }else {
                        JOptionPane.showMessageDialog(null, "Incorrect username.");
                    }
                }
            }
        }
        catch(SQLException e)
        {
          // if the error message is "out of memory",
          // it probably means no database file is found
          System.err.println(e.getMessage());
        }
        finally
        {
          try
          {
            if(connection != null)
              connection.close();
          }
          catch(SQLException e)
          {
            // connection close failed.
            System.err.println(e.getMessage());
          }
        }
    }

    // Prompts the user for a username
    private static String promptUsername() {
        return JOptionPane.showInputDialog("Enter a username:");
    }

    // Prompts the user for a password
    private static String promptPassword() {
        return JOptionPane.showInputDialog("Enter a password:");
    }

    // Validates the username according to the rules
    private static boolean isValidUsername(String username) {
        // Check if the username uses only allowed characters
        if (!username.matches("[a-zA-Z0-9_]+")) {
            JOptionPane.showMessageDialog(null, "Username can only contain letters, numbers, and underscores.");
            return false;
        }
        String usernameNoLeet = username;

        // remove any leet before checking profanity
        usernameNoLeet = usernameNoLeet.replaceAll("1","i");
        usernameNoLeet = usernameNoLeet.replaceAll("3","e");
        usernameNoLeet = usernameNoLeet.replaceAll("4","a");
        usernameNoLeet = usernameNoLeet.replaceAll("5","s");
        usernameNoLeet = usernameNoLeet.replaceAll("7","t");
        usernameNoLeet = usernameNoLeet.replaceAll("0","o");
        usernameNoLeet = usernameNoLeet.replaceAll("9","g");

        // Check if the username uses any swear words
        for (String word : profanityFilter) {
            if (usernameNoLeet.equalsIgnoreCase(word)) {
                JOptionPane.showMessageDialog(null, "Username cannot contain swear words.");
                return false;
            }
        }
        return true;
    }

    // Validates the password according to the NIST guidelines
    private static boolean isValidPassword(String password) {
        // Check NIST guidelines
        if (password.length() < 8) {
            JOptionPane.showMessageDialog(null, "Password must be at least 8 characters long.");
            return false;
        }
        if(password.matches(".*0123456789.*") || password.matches(".*9876543210.*") ||
        password.matches(".*abcdefghijklmnopqrstuvwxyz.*") || password.matches(".*zyxwvutsrqponmlkjihgfedcba.*") || password.matches(".*(.)\\1{2,}.*")){
            JOptionPane.showMessageDialog(null, "Password must not be sequential or have repeated characters.");
            return false;
        }
        if(password == "EnrolmentAndVerification"){
            JOptionPane.showMessageDialog(null, "Password must not be named after this amazing app.");
            return false;
        }
        // Check if password is breached
        for (String weakPassword : breachedPasswords) {
            if (password.equalsIgnoreCase(weakPassword)) {
                JOptionPane.showMessageDialog(null, "Password is too weak. Choose a stronger password.");
                return false;
            }
        }
        return true;
    }

    public static String[] hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        if (salt == null) {
            salt = generateSalt();
            //System.out.println("new Salt Generated: " + salt);
        }else{
            //System.out.println("Salt Re-used: " + salt);
        }
        System.out.println("SALT USED: " + salt);
        System.out.println("password used: " + password);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update((password + salt).getBytes());
        byte[] hashedPasswordBytes = md.digest();
        String hashedPassword = Base64.getEncoder().encodeToString(hashedPasswordBytes);
        String[] hashAndSalt = {hashedPassword, salt};
        System.out.println("hashedpwd: " + hashAndSalt[0] + " salt: " + hashAndSalt[1]);
        return hashAndSalt;
    }

    private static String generateSalt() {
        int SALT_LENGTH = 12;

        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[SALT_LENGTH];
        random.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
