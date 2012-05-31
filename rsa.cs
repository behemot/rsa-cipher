/**
 * RSA cipher http://en.wikipedia.org/wiki/Caesar_cipher
 *
 * Author: Michał Białas <michal.bialas@mbialas.pl>
 * Since: 2012-01-08
 * Version: 0.2
 */

using System;
using System.IO;
using System.Text;
using System.Numerics;
using System.Collections.Generic;
using System.Security.Cryptography;
using NDesk.Options;

public class Rsa
{	
	public static void Main(string[] args)
	{
		bool showHelp = false;
		string key = null, inputPath = null, outputPath = null, publicPath = null, privatePath = null, command;

		OptionSet opt = new OptionSet() {
			{"k|key=", "key file", v => key = v},
			{"i|in=", "input file", v => inputPath = v},
			{"o|out=", "output file", v => outputPath = v},
			{"pub=", "publi key output file", v => publicPath = v},
			{"priv=", "private key output file", v => privatePath = v},
			{"h|help", "show this message and exit", v => showHelp = v != null},
		};

		List<string> commands;
		try {
			commands = opt.Parse(args);
		} catch (OptionException e) {
			PrintError(e.Message);
			return;
		}

		if (showHelp) {
            Usage(opt);
            return;
        }

		if (0 == commands.Count) {
			PrintError("No command error");
			return;
		}
		
		command = commands[0];
		
		if ("encrypt" != command && "decrypt" != command && "keygen" != command) {
			PrintError("Invalid command.");
			return;
		}
		
		if (null == key) {
			PrintError("No key error");
			return;
		}

		if (null == inputPath && "keygen" != command) {
			PrintError("Input file is not specified");
			return;
		}

		if (null == outputPath && "keygen" != command) {
			PrintError("Output file is not specified");
			return;
		}

		FileStream inputFile = null, outputFile = null;
		if ("encrypt" == command || "decrypt" == command) {
			try {
				inputFile = File.Open(inputPath, FileMode.Open, FileAccess.Read, FileShare.None);
				outputFile = File.Open(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
			} catch (Exception e) {
				PrintError(e.Message);
				return;
			}
		}
		
		BigInteger a, b;
		try {
			byte[] keyContent = File.ReadAllBytes(key);
			string[] keys = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(keyContent))).Split(new Char [] {','});
			a = BigInteger.Parse(keys[0]);
			b = BigInteger.Parse(keys[1]);
		} catch (Exception e) {
			PrintError(e.Message);
			return;
		}
		
		FileStream pubFile = null, privFile = null;
		if ("keygen" == command) {
			try {
				pubFile = File.Open(publicPath, FileMode.Create, FileAccess.Write, FileShare.None);
				privFile = File.Open(privatePath, FileMode.Create, FileAccess.Write, FileShare.None);
			} catch (Exception e) {
				PrintError(e.Message);
				return;
			}
		}

		RsaCrypt crypt = new RsaCrypt();
		switch (command) {
			case "keygen":
				crypt.publicFile = pubFile;
				crypt.privateFile = privFile;
				crypt.Keygen(a, b);
				break;
			case "encrypt":
				crypt.inputFile = inputFile;
				crypt.outputFile = outputFile;
				crypt.Encrypt(a, b);
				break;
			case "decrypt":
				crypt.inputFile = inputFile;
				crypt.outputFile = outputFile;
				crypt.Decrypt(a, b);
				break;
		}

		Console.WriteLine("done");
		if (null != inputFile) {
			inputFile.Close();
		}
		if (null != outputFile) {
			outputFile.Close();
		}
		if (null != pubFile) {
			pubFile.Close();
		}
		if (null != privFile) {
			privFile.Close();
		}
	}
	
	public static void Usage(OptionSet opt)
	{
		Console.WriteLine("Usage: rsa.exe (encrypt|decrypt|keygen) /key:key_file /in:inupt_file /out:output_file [/pub:public_key /priv:private_key]");
        Console.WriteLine("Options:");
        opt.WriteOptionDescriptions(Console.Out);
	}
	
	public static void PrintError(string message)
	{
		Console.WriteLine("Error: {0}", message);
		Console.WriteLine ("Try rsa.exe /help for more information.");
	}
}

class RsaCrypt
{
	public const int MAX_CHARS = 256;
	
	public FileStream inputFile { get; set; }
	 
	public FileStream outputFile { get; set; }
	
	public FileStream publicFile { get; set; }
	
	public FileStream privateFile { get; set; }
	 
	public void Decrypt(BigInteger d, BigInteger n)
	{
		int bufferLength = n.ToByteArray().Length;
		byte [] inBuffer = new byte[bufferLength];
		byte [] outBuffer;
		BigInteger m, c;
		while (inputFile.Read(inBuffer, 0, inBuffer.Length) > 0) {
			c = new BigInteger(inBuffer);
			m = BigInteger.ModPow(c, d, n);
			outBuffer = m.ToByteArray();
			outputFile.Write(outBuffer, 0, outBuffer.Length);
		}
	}
	 
	public void Encrypt(BigInteger e, BigInteger n)
	{
		int bufferLength = n.ToByteArray().Length;
		byte [] inBuffer = new byte[bufferLength - 1];
		byte [] outBuffer, tmpBuffer;
		BigInteger m, c;
		while (inputFile.Read(inBuffer, 0, inBuffer.Length) > 0) {
			m = new BigInteger(inBuffer);
			Array.Clear(inBuffer, 0, inBuffer.Length);
			c = BigInteger.ModPow(m, e, n);
			outBuffer = c.ToByteArray();
			if (bufferLength != outBuffer.Length) {
				tmpBuffer = new byte[bufferLength];
				Buffer.BlockCopy(outBuffer, 0, tmpBuffer, 0, outBuffer.Length);
				outBuffer = tmpBuffer;
			}
			outputFile.Write(outBuffer, 0, outBuffer.Length);
		}
	}
	
	public void Keygen(BigInteger p, BigInteger q)
	{
		BigInteger n = p * q;
		BigInteger fi = (p - BigInteger.One) * (q - BigInteger.One);
		var rng = new RNGCryptoServiceProvider();
		byte[] bytes = new byte[fi.ToByteArray().Length - 1];
		BigInteger e;
		do {
			rng.GetBytes(bytes);
			e = new BigInteger(bytes);
		} while (!(e > 1 && e < fi && BigInteger.One == BigInteger.GreatestCommonDivisor(e, fi)));
		BigInteger d = Util.GetModularInverse(e, fi);
		byte [] content = Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(d.ToString() + "," + n.ToString())));
		publicFile.Write(content, 0, content.Length);
		content = Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(e.ToString() + "," + n.ToString())));
		privateFile.Write(content, 0, content.Length);
	}
}

class Util
{	
	public static BigInteger GetModularInverse(BigInteger a, BigInteger b)
	{
		BigInteger p, q, r, s, quotient, tmp, n;
		p = new BigInteger(1); q = new BigInteger(0);
		r = new BigInteger(0); s = new BigInteger(1);
		n = b;

		while (0 != b) {
			tmp = a % b;
			quotient = a / b;
			a = b; b = tmp;
			tmp = p - quotient * r;
			p = r; r = tmp;
			tmp = q - quotient * s;
			q = s;
			s = tmp;
		}

		return 1 == p.Sign ? p : p + n;
	}
}
