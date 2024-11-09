using System.Text;

namespace XorStr
{
    internal static class Runtime
    {
        // Basic XOR encryption/decryption method
        public static string XOR(string text, int key)
        {
            // Create a StringBuilder to hold the XORed result
            StringBuilder input = new StringBuilder(text);

            // Iterate over each character in the string
            for (int i = 0; i < text.Length; i++)
                // Apply XOR operation on each character using the provided key
                input[i] = (char)(input[i] ^ key);

            // Return the XORed string
            return input.ToString();
        }
    }
}