using Confuser.Core.Helpers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.IO;
using System.Linq;

namespace XorStr
{
    internal class Program
    {
        static string filePath = string.Empty, outputFilePath = string.Empty;
        static ModuleDefMD Module = null;
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

            // Load the module (file) into memory
            Module = ModuleDefMD.Load(filePath);

            // Create output file path by inserting "-XoredStrings" before the file extension (e.g., .dll or .exe)
            outputFilePath = filePath.Insert(filePath.Length - 4, "-XoredStrings");

            // Load the current assembly (self) and inject the runtime decryption method
            ModuleDefMD selfModule = ModuleDefMD.Load(typeof(Runtime).Module); // Load this program's assembly
            TypeDef selfModuleTypeDef = selfModule.GetTypes().First(T => T.Name == nameof(Runtime)); // Get the Runtime type from this assembly

            // Inject the XOR decryption method from Runtime into the target module's global type
            MethodDef DecryptMethod = (MethodDef)InjectHelper.Inject(selfModuleTypeDef, Module.GlobalType, Module)
                .First(M => M.Name == nameof(Runtime.XOR)); // Find and inject the XOR method

            // Iterate over all types, skipping the global module type
            foreach (TypeDef Type in Module.GetTypes().Where(T => !T.IsGlobalModuleType))
                // Filter methods that have a body with more than one instruction
                foreach (MethodDef Method in Type.Methods.Where(M => M.HasBody && M.Body.HasInstructions && M.Body.Instructions.Count() > 1))
                {
                    // Generate a random XOR key between 10 and 100 for each method
                    int xorKey = new Random().Next(10, 100);

                    // Iterate through each instruction in the method's body
                    for (int i = 0; i < Method.Body.Instructions.Count(); i++)
                    {
                        Instruction Instruction = Method.Body.Instructions[i];

                        // Check if the current instruction is a string load instruction (Ldstr)
                        if (Instruction.OpCode == OpCodes.Ldstr)
                        {
                            // Get the original string operand from the instruction
                            string theStringToProcess = Instruction.Operand.ToString();

                            // XOR the string with the generated key
                            string theProcessedString = Runtime.XOR(theStringToProcess, xorKey);

                            // Replace the original string with the XORed version
                            Instruction.Operand = theProcessedString;

                            // Insert the XOR key as a new instruction right after the XORed string
                            Method.Body.Instructions.Insert(i + 1, OpCodes.Ldc_I4.ToInstruction(xorKey));

                            // Insert the decryption method call instruction after the XOR key
                            Method.Body.Instructions.Insert(i + 2, OpCodes.Call.ToInstruction(DecryptMethod));

                            // Increment the index by 2 to skip over the newly inserted instructions
                            i += 2;
                        }
                    }
                }

            // Write the modified module to the output file
            Module.Write(outputFilePath);
        }
    }
}