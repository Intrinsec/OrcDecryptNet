using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using System.Buffers.Binary;
using Microsoft.Extensions.Logging;


namespace OrcDecryptNet
{
    public class DfirOrcDecryption(ILogger<DfirOrcDecryption> logger)
    {
        private readonly ILogger<DfirOrcDecryption> _logger = logger;
        public static byte[] rsaOaepOid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07 };
        public static byte[] rsaEncryptionOid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
        public static byte[] pkcs7DataOid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };

        public bool DecryptArchive(
            string p7bPath,
            string outputFolder,
            string privateKeyPath,
            HashAlgorithmName hashAlgorithm = default,
            string password = "")
        {
            if (hashAlgorithm == default)
            {
                hashAlgorithm = HashAlgorithmName.SHA1;  // Use SHA1 as in the original script
            }

            // Read the private key from file
            using RSA privateKey = CommonCrypto.LoadPrivateKeyFromPfx(privateKeyPath, password);
            if (privateKey == null)
            {
                this._logger.LogDebug("Invalid private key.");
                return false;
            }
            return ProcessArchive(p7bPath, privateKey, outputFolder);
        }

        public static int FindOffset(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pattern)
        {
            if (pattern.Length == 0)
                return 0;

            int[] lps = BuildLpsArray(pattern);

            int i = 0; // index for data
            int j = 0; // index for pattern

            while (i < data.Length)
            {
                if (pattern[j] == data[i])
                {
                    i++;
                    j++;

                    if (j == pattern.Length)
                    {
                        return i - j;
                    }
                }
                else
                {
                    if (j != 0)
                    {
                        j = lps[j - 1];
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            return -1;
        }

        private static int[] BuildLpsArray(ReadOnlySpan<byte> pattern)
        {
            int[] lps = new int[pattern.Length];
            int length = 0;
            int i = 1;

            while (i < pattern.Length)
            {
                if (pattern[i] == pattern[length])
                {
                    length++;
                    lps[i] = length;
                    i++;
                }
                else
                {
                    if (length != 0)
                    {
                        length = lps[length - 1];
                    }
                    else
                    {
                        lps[i] = 0;
                        i++;
                    }
                }
            }

            return lps;
        }


        public static List<int> FindAllOccurrences(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pattern)
        {
            List<int> occurrences = new List<int>();

            if (pattern.Length == 0 || data.Length < pattern.Length)
            {
                return occurrences;
            }

            int[] lps = BuildLpsArray(pattern);

            int i = 0; // index for data
            int j = 0; // index for pattern

            while (i < data.Length)
            {
                if (pattern[j] == data[i])
                {
                    i++;
                    j++;

                    if (j == pattern.Length)
                    {
                        occurrences.Add(i - j);
                        j = lps[j - 1];
                    }
                }
                else
                {
                    if (j != 0)
                    {
                        j = lps[j - 1];
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            return occurrences;
        }

        public static int ConvertToIntBigEndian(ReadOnlySpan<byte> byteArray)
        {
            return byteArray.Length switch
            {
                1 => byteArray[0],
                2 => BinaryPrimitives.ReadInt16BigEndian(byteArray),
                4 => BinaryPrimitives.ReadInt32BigEndian(byteArray),
                _ => throw new ArgumentException("Unsupported byte array length for integer conversion")
            };
        }

        public bool ProcessArchive(string p7bPath, RSA privateKey, string outputFolder)
        {
            string outputPath = Path.Combine(outputFolder, Path.GetFileNameWithoutExtension(p7bPath));
            byte[] s = new byte[10 * 1024];

            using (FileStream fs = new FileStream(p7bPath, FileMode.Open, FileAccess.Read))
            {
                int bytesRead = fs.Read(s, 0, s.Length);

                if (bytesRead < s.Length)
                {
                    Array.Resize(ref s, bytesRead);
                }
            }

            int pkcs7DataOffset = FindOffset(s, pkcs7DataOid);
            if (pkcs7DataOffset < 0)
            {
                this._logger.LogDebug("PKCS#7 data OID not found in file header.");
                return false;
            }

            int pkcs7Offset = pkcs7DataOffset + pkcs7DataOid.Length + 2;
            if (pkcs7Offset + 1 >= s.Length)
            {
                this._logger.LogDebug("PKCS#7 header is truncated before symmetric OID.");
                return false;
            }

            int oidLen = s[pkcs7Offset + 1];
            if (pkcs7Offset + oidLen + 1 >= s.Length)
            {
                this._logger.LogDebug("Symmetric OID extends past the PKCS#7 header buffer.");
                return false;
            }

            byte[] oidBytes = new byte[oidLen + 2];
            Array.Copy(s, pkcs7Offset, oidBytes, 0, oidLen + 2);

            string symEncOid = CommonCrypto.DecodeOid(oidBytes);

            int ivOffset = pkcs7Offset + oidLen + 2;
            if (ivOffset + 1 >= s.Length)
            {
                this._logger.LogDebug("PKCS#7 header is truncated before IV.");
                return false;
            }

            int ivLen = s[ivOffset + 1];
            if (ivOffset + ivLen + 1 >= s.Length)
            {
                this._logger.LogDebug("IV extends past the PKCS#7 header buffer.");
                return false;
            }

            byte[] iv = new byte[ivLen];
            Array.Copy(s, ivOffset + 2, iv, 0, ivLen);

            var matchRsaOaep = FindAllOccurrences(s, rsaOaepOid);
            var matchRsaEncryption = FindAllOccurrences(s, rsaEncryptionOid);

            this._logger.LogDebug("Symmetric Encryption OID: " + symEncOid);
            this._logger.LogDebug("IV (Hex): " + BitConverter.ToString(iv));
            this._logger.LogDebug("RSA OAEP Matches: " + matchRsaOaep.Count);
            this._logger.LogDebug("RSA Encryption Matches: " + matchRsaEncryption.Count);

            byte[]? symkey = null;
            SymmetricAlgorithm? cipher = null;

            if (matchRsaOaep.Count > 0)
            {
                foreach (int match in matchRsaOaep)
                {
                    int keyOffset = match + rsaOaepOid.Length + 4;
                    if (keyOffset + 1 >= s.Length)
                    {
                        continue;
                    }

                    ushort encSymKeyLen = (ushort)((s[keyOffset] << 8) | s[keyOffset + 1]);
                    if (keyOffset + 2 + encSymKeyLen > s.Length)
                    {
                        continue;
                    }

                    byte[] encSymKey = new byte[encSymKeyLen];
                    Array.Copy(s, keyOffset + 2, encSymKey, 0, encSymKeyLen);

                    this._logger.LogDebug($"Found potential RSAES-OAEP OID at offset 0x{match:X}, with encrypted symmetric key length {encSymKeyLen}");

                    try
                    {
                        symkey = privateKey.Decrypt(encSymKey, RSAEncryptionPadding.OaepSHA1);
                        cipher = CommonCrypto.GetCipher(symEncOid, symkey, iv);
                        this._logger.LogDebug($"Successfully decrypted symmetric key (length {symkey.Length}) for RSAES-OAEP OID at offset 0x{match:X}");
                        break;
                    }
                    catch (CryptographicException e)
                    {
                        this._logger.LogDebug($"Failed to decrypt symmetric key for RSAES-OAEP OID at offset 0x{match:X}: {e.Message}");
                    }
                }
            }

            if (symkey == null && matchRsaEncryption.Count > 0)
            {
                foreach (int match in matchRsaEncryption)
                {
                    int keyOffset = match + rsaEncryptionOid.Length + 2;
                    if (keyOffset + 1 >= s.Length)
                    {
                        continue;
                    }

                    ushort encSymKeyLen = (ushort)((s[keyOffset] << 8) | s[keyOffset + 1]);
                    if (keyOffset + 2 + encSymKeyLen > s.Length)
                    {
                        continue;
                    }

                    byte[] encSymKey = new byte[encSymKeyLen];
                    Array.Copy(s, keyOffset + 2, encSymKey, 0, encSymKeyLen);

                    this._logger.LogDebug($"Found potential rsaEncryption OID at offset 0x{match:X}, with encrypted symmetric key length {encSymKeyLen}");

                    try
                    {
                        symkey = privateKey.Decrypt(encSymKey, RSAEncryptionPadding.Pkcs1);
                        cipher = CommonCrypto.GetCipher(symEncOid, symkey, iv);
                        this._logger.LogDebug($"Successfully decrypted symmetric key (length {symkey.Length}) for rsaEncryption OID at offset 0x{match:X}");
                        break;
                    }
                    catch (CryptographicException e)
                    {
                        this._logger.LogDebug($"Failed to decrypt symmetric key for rsaEncryption OID at offset 0x{match:X}: {e.Message}");
                    }
                }
            }

            if (symkey == null || cipher == null)
            {
                this._logger.LogDebug("Failed to decrypt any symmetric key.");
                return false;
            }

            int contentOffset = ivOffset + ivLen + 2;

            if (contentOffset + 1 < s.Length && (s[contentOffset] != 0xA0 || s[contentOffset + 1] != 0x80))
            {
                int snippetOffset = Math.Max(contentOffset - 10, 0);
                int snippetLength = Math.Min(30, s.Length - snippetOffset);
                string hexSnippet = BitConverter.ToString(s, snippetOffset, snippetLength).Replace("-", "");
                int foundIndex = Array.IndexOf(s, 0xA0, 813);

                this._logger.LogDebug($"File does not match what we expected (\\xA0\\x80) at offset {contentOffset}: {hexSnippet}. Found at {foundIndex}");
                return false;
            }

            using var decryptor = cipher.CreateDecryptor(symkey, iv);
            long p7bFileSize = new FileInfo(p7bPath).Length;
            using MemoryMappedFile mmfIn = MemoryMappedFile.CreateFromFile(p7bPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using MemoryMappedViewStream fIn = mmfIn.CreateViewStream(0, 0, MemoryMappedFileAccess.Read);

            var fOutTempPath = outputPath + "s";
            using MemoryMappedFile mmfOutTemp = MemoryMappedFile.CreateFromFile(fOutTempPath, FileMode.Create, null, p7bFileSize, MemoryMappedFileAccess.ReadWrite);
            using MemoryMappedViewStream fOutTemp = mmfOutTemp.CreateViewStream(0, 0, MemoryMappedFileAccess.ReadWrite);

            using MemoryMappedFile mmfOut = MemoryMappedFile.CreateFromFile(outputPath, FileMode.Create, null, p7bFileSize, MemoryMappedFileAccess.ReadWrite);
            using MemoryMappedViewStream fOut = mmfOut.CreateViewStream(0, 0, MemoryMappedFileAccess.ReadWrite);

            using MemoryStream memDecrypted = new MemoryStream();

            fIn.Seek(contentOffset + 2, SeekOrigin.Begin);
            int BUFFER_SIZE = 0;
            int t = fIn.ReadByte();
            int c = fIn.ReadByte();
            int decryptedBytesCount = 0;
            byte[] decryptedData = new byte[0];
            bool isJRNL = false;
            bool firstBlockDecrypted = false;
            using var loggerFactory = LoggerFactory.Create(builder =>
            {

                builder.SetMinimumLevel(LogLevel.Debug);
            });
            ILogger<DfirOrcUnstream> loggerDfirOrcUnstream = loggerFactory.CreateLogger<DfirOrcUnstream>();
            DfirOrcUnstream unstream = new DfirOrcUnstream(loggerDfirOrcUnstream);
            while (t == 0x04)
            {
                int oslen;
                if ((c & 0x80) == 0)
                {
                    oslen = c;
                }
                else
                {
                    int numBytes = c & 0x7F;
                    byte[] lenBytes = new byte[numBytes];

                    if (fIn.Read(lenBytes, 0, numBytes) != numBytes)
                    {
                        throw new Exception("Unexpected data length");
                    }

                    oslen = ConvertToIntBigEndian(lenBytes);
                }
                byte[] encryptedData = new byte[oslen];
                if (fIn.Read(encryptedData, 0, oslen) != oslen) 
                    break;

                decryptedData = new byte[encryptedData.Length];
                try
                {
                    if (encryptedData.Length < BUFFER_SIZE)
                    {
                        decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                        decryptedBytesCount = decryptedData.Length;
                    }
                    else
                    {
                        decryptedBytesCount = decryptor.TransformBlock(encryptedData, 0, encryptedData.Length, decryptedData, 0);
                    }

                    if (!firstBlockDecrypted)
                    {
                        firstBlockDecrypted = true;
                        isJRNL = decryptedData.Take(4).SequenceEqual(DfirOrcUnstream.MAGIC_JRNL);
                        this._logger.LogDebug(isJRNL ? "Decrypted file is JRNL stream" : "Decrypted file is not JRNL stream");
                    }

                    if (isJRNL && p7bFileSize < Int32.MaxValue)
                    {
                        memDecrypted.Write(decryptedData, 0, decryptedBytesCount);
                    }
                    else if (isJRNL)
                    {
                        fOutTemp.Write(decryptedData, 0, decryptedBytesCount);
                    }
                    else
                    {
                        fOut.Write(decryptedData, 0, decryptedBytesCount);
                    }
                
                }
                catch (CryptographicException e)
                {
                    this._logger.LogDebug($"Failed to decrypt {oslen} bytes: {e.Message}");
                    return false;
                }
                t = fIn.ReadByte();
                c = fIn.ReadByte();
                BUFFER_SIZE = oslen;
            }
            if (isJRNL && p7bFileSize < Int32.MaxValue)
            {
                unstream.DoUnstream(memDecrypted, fOut);
                this._logger.LogDebug("File is less than " + Int32.MaxValue + " bytes.");
                this._logger.LogDebug("Running Unstream from Memory Stream");
            }
            else if (isJRNL && p7bFileSize >= Int32.MaxValue)
            {
                unstream.DoUnstream(fOutTemp, fOut);
                this._logger.LogDebug("File is bigger than " + Int32.MaxValue + " bytes.");
                this._logger.LogDebug("Running Unstream from temp file:" + fOutTempPath);
            }
            if (File.Exists(fOutTempPath))
            { 
                File.Delete(fOutTempPath);
            }
            this._logger.LogDebug("Successfully decrypted: {OutputPath}", outputPath);
            return true;
        }

    }
}
