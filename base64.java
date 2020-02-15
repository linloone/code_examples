import java.util.ArrayList;
import java.util.Scanner;

public class base64
{

    private static int base10Index( String s )
    {
        try
        {
            return Integer.parseInt( s );
        }
        catch ( NumberFormatException e )
        {
            switch ( s.toLowerCase() )
            {
                case "a": return 0xa;
                case "b": return 0xb;
                case "c": return 0xc;
                case "d": return 0xd;
                case "e": return 0xe;
                case "f": return 0xf;
                
                default:  return -1;
            }
        }
    }
    
    public static String encode( ArrayList<Byte> inp )
    {
        ArrayList<Byte> data = inp;
        
        char[] charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        
        StringBuilder encodedString = new StringBuilder("");
        
        // this is the number of blocks - since each block
        // is 3 bytes, we get the total number of full blocks 
        // (blocks that are a full 3 bytes long)
        // by dividing the length of the input by 3.
        //
        // then, we can get the number of bytes leftover
        // if the input is not at a byte length evenly divisible by 3 
        // by using the remainder/modulo operator (%)
        int numBlocks = data.size() / 3;
        int numLeftoverBytes = data.size() % 3;
        
        // if the input is not evenly divisible by 3 bytes, and we
        // have some remainder leftover, lets figure out how many
        // bytes we need to pad it with in order to make it a
        // full block
        if ( numLeftoverBytes > 0 )
        {
            int numPadBytes = 3 - numLeftoverBytes;
            
            for ( int i = 0; i < numPadBytes; ++i )
            {
                data.add( Byte.decode("0") );
            }
        }
        
        // if we received less than three bytes of input, we now have one
        // full block to work with after padding!
        if ( numBlocks == 0 )
            { numBlocks = 1; }
        
        for ( int i = 0; i < numBlocks; ++i )
        {
            // since the data is now perfectly divisible by 3
            // bytes, we can rest assured that we will not be
            // operating on incomplete blocks
            
            // we will take the three individual bytes and turn them
            // into one block by adding them up into a single integer.
            //
            // we need to shift bits here while adding to do this.
            int block = 0;
            
            block  = data.get((3*i))   << 16;
            block += data.get((3*i)+1) << 8;
            block += data.get((3*i)+2);
            
            System.out.println("Block: " + block);
            
            // now that weve constructed the block, lets use bit masking
            // and shifting to get each group of six bytes.
            int group1 = (block >> 18) & 0x00003F;
            int group2 = (block >> 12) & 0x00003F;
            int group3 = (block >> 6)  & 0x00003F;
            int group4 = block & 0x00003F;
            
            System.out.println("group1: " + group1);
            System.out.println("group2: " + group2);
            System.out.println("group3: " + group3);
            System.out.println("group4: " + group4);
            
            // now its just a matter of mapping those to our character
            // set at the top of the function
            encodedString.append( charset[group1] );
            encodedString.append( charset[group2] );
            encodedString.append( charset[group3] );
            encodedString.append( charset[group4] );
        }
        
        // for every byte we had to pad onto the input to make it
        // evenly divisible by 3, we have to replace that many 
        // characters at the end with '='
        if ( numLeftoverBytes > 0 ) 
            { encodedString.setCharAt( encodedString.length() - 1, '=' ); }
    
        if ( numLeftoverBytes > 1 )
            { encodedString.setCharAt( encodedString.length() - 2, '=' ); }
        
        // aaaaaaaaand we're done!
        return encodedString.toString();
    }


    public static void main( String[] args )
    {
        System.out.println( "Enter a string (in hex): " );
        ArrayList<Byte> input = new ArrayList<Byte>();
        
        Scanner sc = new Scanner( System.in );
        String inp = sc.nextLine();
        
        for ( int i = 0; i < inp.length()/2; ++i )
        {
            // parse two hex chars at a time for 1 byte
            int index = i * 2;
            
            byte val = 0;
            val =  (byte)(base10Index( String.valueOf(inp.charAt(index)) ) << 4);
            val += (byte)base10Index( String.valueOf(inp.charAt(index+1)) );
            
            System.out.println("Adding " + val);
            input.add( val );
        }
        
        System.out.println( encode(input) );
    }
}