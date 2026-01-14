using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OrcDecryptNet
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public class CredentialStorage
    {
        private readonly ILogger<CredentialStorage> _logger;
        private readonly string _credentialsPath;

        private struct StoredCredentials
        {
            public string PrivateKeyPath { get; set; }
            public string EncryptedPassword { get; set; }
        }

        public CredentialStorage(ILogger<CredentialStorage> logger)
        {
            _logger = logger;
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            _credentialsPath = Path.Combine(userProfile, ".orcuac_credentials");
        }

        public bool HasStoredCredentials()
        {
            return File.Exists(_credentialsPath);
        }

        public void StoreCredentials(string privateKeyPath, string password)
        {
            try
            {
                var encryptedPassword = ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(password),
                    null,
                    DataProtectionScope.CurrentUser
                );

                var credentials = new StoredCredentials
                {
                    PrivateKeyPath = privateKeyPath,
                    EncryptedPassword = Convert.ToBase64String(encryptedPassword)
                };

                var json = JsonSerializer.Serialize(credentials);
                File.WriteAllText(_credentialsPath, json);

                _logger.LogInformation("Credentials stored successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to store credentials: {Message}", ex.Message);
                throw;
            }
        }

        public (string privateKeyPath, string password) LoadCredentials()
        {
            try
            {
                if (!File.Exists(_credentialsPath))
                {
                    throw new FileNotFoundException("No stored credentials found");
                }

                var json = File.ReadAllText(_credentialsPath);
                var credentials = JsonSerializer.Deserialize<StoredCredentials>(json);

                var encryptedPassword = Convert.FromBase64String(credentials.EncryptedPassword);
                var decryptedPassword = ProtectedData.Unprotect(
                    encryptedPassword,
                    null,
                    DataProtectionScope.CurrentUser
                );

                var password = Encoding.UTF8.GetString(decryptedPassword);

                _logger.LogDebug("Credentials loaded successfully");
                return (credentials.PrivateKeyPath, password);
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to load credentials: {Message}", ex.Message);
                throw;
            }
        }

        public void ClearStoredCredentials()
        {
            try
            {
                if (File.Exists(_credentialsPath))
                {
                    File.Delete(_credentialsPath);
                    _logger.LogInformation("Stored credentials cleared");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to clear credentials: {Message}", ex.Message);
                throw;
            }
        }
    }
}