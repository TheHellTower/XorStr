using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace XorStr_Decrypt
{
    internal class Program
    {
        static string filePath = string.Empty, outputFilePath = string.Empty;
        static ModuleDefMD Module = null;
        static Assembly Assembly = null;
        static void Main(string[] args)
        {
            // Handle file path input from command-line arguments or user input
            if (args.Length != 0)
                filePath = args[0].Replace("\"", string.Empty);
            while (!File.Exists(filePath)) // Keep asking for file path until a valid one is provided
            {
                Console.WriteLine("File Path: ");
                filePath = Console.ReadLine().Replace("\"", string.Empty);
            }

            // Load the module (file) and assembly into memory
            Module = ModuleDefMD.Load(filePath);
            Assembly = Assembly.LoadFrom(Module.Location);

            // Create output file path by inserting "-Decrypted" before the file extension (e.g., .dll or .exe)
            outputFilePath = filePath.Insert(filePath.Length - 4, "-Decrypted");

            // Iterate over all types, skipping the global module type
            foreach (TypeDef Type in Module.GetTypes().Where(T => !T.IsGlobalModuleType))
                // Filter methods that have a body with more than one instruction
                foreach (MethodDef Method in Type.Methods.Where(M => M.HasBody && M.Body.HasInstructions && M.Body.Instructions.Count() > 1))
                {
                    // Iterate through each instruction in the method's body
                    for (int i = 0; i < Method.Body.Instructions.Count(); i++)
                    {
                        Instruction Instruction = Method.Body.Instructions[i];

                        // Check if the current instruction is a method call and follows a specific pattern:
                        // - Instruction before the call is an integer (Ldc_I4)
                        // - Two instructions before the call is a string (Ldstr)
                        if (Instruction.OpCode == OpCodes.Call &&
                            Method.Body.Instructions[i - 1].OpCode == OpCodes.Ldc_I4 &&
                            Method.Body.Instructions[i - 2].OpCode == OpCodes.Ldstr)
                        {
                            /* Pattern to match:
                             * 1. ldstr    "Encrypted String"
                             * 2. ldc.i4   0 (key)
                             * 3. call     string '<Module>'::XOR(string, int32)
                             */

                            // Cast the operand of the call instruction to MethodDef for further analysis
                            MethodDef StringMethod = Instruction.Operand as MethodDef;

                            // Validate the method: check if it returns a string and has two parameters (string and integer)
                            if (StringMethod != null &&
                                StringMethod.ReturnType.ToString() == "System.String" &&
                                StringMethod.Parameters.Count() == 2)
                            {
                                try
                                {
                                    // Extract the string operand from two instructions before the call
                                    string theStringToProcess = Method.Body.Instructions[i - 2].Operand.ToString();

                                    // Extract the integer operand (XOR key) from one instruction before the call
                                    int theXorKey = Convert.ToInt32(Method.Body.Instructions[i - 1].Operand);

                                    // Caution: Invoking methods could be dangerous if the code contains malicious anti-invoke logic!
                                    // Always analyze the code before using this.
                                    string theProcessedString = (string)Assembly.ManifestModule
                                        .ResolveMethod((int)StringMethod.MDToken.Raw)
                                        .Invoke(null, new object[] { theStringToProcess, theXorKey });

                                    // Output the decrypted string
                                    Console.WriteLine($"[Restored] {theProcessedString}");

                                    // Replace the call instruction with the decrypted string (Ldstr opcode)
                                    Instruction.OpCode = OpCodes.Ldstr;
                                    Instruction.Operand = theProcessedString;

                                    // Remove the old XORed string and XOR key instructions
                                    Method.Body.Instructions.RemoveAt(i - 2); // Remove the XORed string
                                    Method.Body.Instructions.RemoveAt(i - 2); // Remove the XOR key (same index after previous removal)
                                }
                                catch (Exception ex)
                                {
                                    // Handle failures, possibly due to anti-invoke measures, incorrect arguments, etc.
                                    Console.WriteLine(ex.ToString());
                                }
                            }
                        }
                    }
                }

            // Write the modified module to the output file
            Module.Write(outputFilePath);
        }
    }
}