package uk.co.awpeacock.security;

import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Cipher 
{

    private static final Logger LOGGER = Logger.getLogger(Cipher.class.getName());
    
    /**
     * Our main method - this can be used to test the encode method via the command line.
     *  
     * @param args No command line arguments are required, these will be ignored
     */
    public static void main(String[] args)
    {
        Scanner scanner= new Scanner(System.in);

        System.out.println("Enter message:");
        String message = scanner.nextLine();
        try
        {
            String encoded = Cipher.encode(message);
            System.out.println("\nEncoded message:\n" + encoded);
        }
        catch ( SecurityException e )
        {
            System.out.println(e.getMessage());
        }

        System.out.println("\n--------------------\n\nEnter encrypted message:");
        String encoded = scanner.nextLine();
        try
        {
            String decoded = Cipher.decode(encoded);
            System.out.println("\nDecoded message:\n" + decoded);
        }
        catch ( SecurityException e )
        {
            System.out.println(e.getMessage());
        }

        scanner.close();

    }
    
    /** 
     * This method will encode a string, automatically allowing whitespace as valid characters.
     * 
     * @param original The string to be encoded - should contain only letters (a-z or A-Z) or spaces
     * @return String The encoded string
     * @throws SecurityException if an invalid string has been passed in
     */
    public static final String encode(String original) throws SecurityException
    {
        return Cipher.encode(original, true);
    }

    /** 
     * This method will encode a string.
     * 
     * @param original The string to be encoded - should contain only letters (a-z or A-Z)
     * @param whitespace Whether to also allow whitespace as valid characters
     * @return String The encoded string
     * @throws SecurityException if an invalid string has been passed in
     */
    public static final String encode(String original, boolean whitespace) throws SecurityException
    {
        // Any whitespace at the start or end is unnecessary bloat (and could invalidate an otherwise valid string)
        original = original.trim();

        // The regex will capture this later on, but this saves unnecessary processing and provides a more
        // specific, helpful message
        if ( original.length() == 0 )
        {
            LOGGER.log(Level.FINE, "Attempt to use encode() with an empty string");
            throw new SecurityException("Empty string passed in to encode");
        }

        // We haven't specified that text MUST be in upper case, so translate here.
        // If we determine later on, that lowercase is not allowed then we will throw an exception instead.
        String upper = original.toUpperCase();

        // Make sure we only have letters 
        // Should we be thinking about allowing spaces?
        Pattern pattern = (whitespace? Pattern.compile("^[A-Z\\s]+$") : Pattern.compile("^[A-Z]+$"));
        Matcher matcher = pattern.matcher(upper);
        if ( !matcher.find() )
        {
            LOGGER.log(Level.FINE, "Attempt to use encode() with an invalid string - " + original);
            throw new SecurityException("Invalid string passed in to encode");
        }

        StringBuilder encoded = new StringBuilder();
        StringBuilder log = new StringBuilder();
        char[] chars = upper.toCharArray();
        for ( char c : chars )
        {
            int ascii = (int)c;
            if ( whitespace && ascii < 65 )
            {
                log.append(" ");
                encoded.append(" ");
            }
            else
            {
                int numeric = ascii-65;
                // Confirmation needed - how to handle XYZ has not been explictly set.
                // However, if we just increment by 3 for all chars, then non-alphabetical characters
                // will be output in the encoded value so, until clarification received, we'll loop
                // back to the start
                int converted = (numeric > 22 ? numeric - 23 : numeric + 3);
                log.append(c + " " + converted + " ");
                encoded.append((char)(converted+65));
            }
        }
        LOGGER.log(Level.FINEST, log.toString());
        return encoded.toString();
    }

    /** 
     * This method will decode a previously encodedstring, automatically allowing whitespace as valid characters.
     * 
     * @param original The encoded string to be decoded - should contain only letters (a-z or A-Z) or spaces
     * @return String The encoded string
     * @throws SecurityException if an invalid string has been passed in
     */
    public static final String decode(String original) throws SecurityException
    {
        return Cipher.decode(original, true);
    }

    /** 
     * This method will decoded a previously encoded string.
     * 
     * @param original The encoded string to be decoded - should contain only letters (a-z or A-Z)
     * @param whitespace Whether to also allow whitespace as valid characters
     * @return String The decoded string
     * @throws SecurityException if an invalid string has been passed in
     */
    public static final String decode(String original, boolean whitespace) throws SecurityException
    {
        // Any whitespace at the start or end is unnecessary bloat (and could invalidate an otherwise valid string)
        original = original.trim();

        // The regex will capture this later on, but this saves unnecessary processing and provides a more
        // specific, helpful message
        if ( original.length() == 0 )
        {
            LOGGER.log(Level.FINE, "Attempt to use decode() with an empty string");
            throw new SecurityException("Empty string passed in to decode");
        }

        // We haven't specified that text MUST be in upper case, so translate here.
        // If we determine later on, that lowercase is not allowed then we will throw an exception instead.
        String upper = original.toUpperCase();

        // Make sure we only have letters 
        // Should we be thinking about allowing spaces?
        Pattern pattern = (whitespace? Pattern.compile("^[A-Z\\s]+$") : Pattern.compile("^[A-Z]+$"));
        Matcher matcher = pattern.matcher(upper);
        if ( !matcher.find() )
        {
            LOGGER.log(Level.FINE, "Attempt to use decode() with an invalid string - " + original);
            throw new SecurityException("Invalid string passed in to decode");
        }

        StringBuilder decoded = new StringBuilder();
        StringBuilder log = new StringBuilder();
        char[] chars = upper.toCharArray();
        for ( char c : chars )
        {
            int ascii = (int)c;
            if ( whitespace && ascii < 65 )
            {
                log.append(" ");
                decoded.append(" ");
            }
            else
            {
                int numeric = ascii-65;
                // Confirmation needed - how to handle XYZ (in the original string) has not been explictly set.
                // However, if we just decrement by 3 for all chars, then non-alphabetical characters
                // will be output in the decoded value for ABC so, until clarification received, we'll loop
                // back to the start
                int converted = (numeric < 3 ? numeric + 23 : numeric - 3);
                log.append(c + " " + converted + " ");
                decoded.append((char)(converted+65));
            }

        }
        LOGGER.log(Level.FINEST, log.toString());
        return decoded.toString();
    }

}