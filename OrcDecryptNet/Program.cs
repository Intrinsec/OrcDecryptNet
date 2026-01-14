using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using OrcDecryptNet;
class Program
{
    public static readonly string VERSION = "2.1.0";
    private static ILogger<Program>? _logger;
    private static ILogger<DfirOrcDecryption>? _loggerDfirOrcDecryption;
    private static ILogger<CredentialStorage>? _loggerCredentialStorage;
    public static readonly byte[] MAGIC_PKCS = new byte[]{0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D ,0x01, 0x07, 0x03, 0xA0, 0x80, 0x30 };

    static int Main(string[] args)
    {
        // Check for help first
        if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
        {
            ShowHelp();
            return 0;
        }

        bool verbose = args.Contains("-v") || args.Contains("--verbose");

        // Remove verbose flags from args for processing
        args = args.Where(arg => arg != "-v" && arg != "--verbose").ToArray();

        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            if (verbose)
            {
                builder
                    .SetMinimumLevel(LogLevel.Debug).AddSimpleConsole(options =>
                    {
                        options.IncludeScopes = true;
                        options.SingleLine = true;
                        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
                    });
            }
            else
            {
                builder
                    .SetMinimumLevel(LogLevel.Information).AddConsole();
            }
        });

        _logger = loggerFactory.CreateLogger<Program>();
        _loggerDfirOrcDecryption = loggerFactory.CreateLogger<DfirOrcDecryption>();
        _logger.LogInformation("OrcDecryptNet VERSION={}", VERSION);

        // Check args
        if (args.Length < 1)
        {
            ShowHelp();
            return 0xA0;
        }

        CredentialStorage? credentialStorage = null;
        if (OperatingSystem.IsWindows())
        {
            _loggerCredentialStorage = loggerFactory.CreateLogger<CredentialStorage>();
            credentialStorage = CreateCredentialStorage(_loggerCredentialStorage);
        }

        if (args[0] == "--setup")
        {
            if (!OperatingSystem.IsWindows())
            {
                if (verbose)
                    _logger.LogError("Credential storage is only supported on Windows (requires DPAPI)");
                else
                    Console.WriteLine("Error: Credential storage is only supported on Windows. Please use manual mode with explicit key/password arguments.");
                return 0xA0;
            }
            return HandleSetupCredentials(args, credentialStorage!, verbose);
        }

        if (args[0] == "--clear-credentials")
        {
            if (!OperatingSystem.IsWindows())
            {
                if (verbose)
                    _logger.LogError("Credential storage is only supported on Windows (requires DPAPI)");
                else
                    Console.WriteLine("Error: Credential storage is only supported on Windows. Please use manual mode with explicit key/password arguments.");
                return 0xA0;
            }
            try
            {
                credentialStorage!.ClearStoredCredentials();
                if (verbose)
                    _logger.LogInformation("Stored credentials cleared successfully");
                else
                    Console.WriteLine("✓ Stored credentials cleared successfully");
            }
            catch (Exception ex)
            {
                if (verbose)
                    _logger.LogError("Failed to clear credentials: {Message}", ex.Message);
                else
                    Console.WriteLine($"Error: Failed to clear credentials: {ex.Message}");
                return 0xA3;
            }
            return 0;
        }

        string encryptedArchivePath = args[0];
        string outputFolder;
        string privateKeyPath;
        string password;

        if (OperatingSystem.IsWindows() && credentialStorage != null && credentialStorage.HasStoredCredentials())
        {
            (privateKeyPath, password) = credentialStorage.LoadCredentials();
            outputFolder = args.Length > 1 ? args[1] : Path.GetDirectoryName(encryptedArchivePath) ?? Environment.CurrentDirectory;
        }
        else
        {
            if (args.Length < 3)
            {
                if (verbose)
                    _logger.LogError("No stored credentials found. Please provide private key and password or run --setup first.");
                else
                    Console.WriteLine("Error: No stored credentials found. Please provide private key and password or run --setup first.");
                return 0xA0;
            }
            outputFolder = args[1];
            privateKeyPath = args[2];
            password = args.Length > 3 ? args[3] : "";
        }

        try
        {
            var inF = File.OpenRead(encryptedArchivePath);
            byte[] header = new byte[MAGIC_PKCS.Length];
            inF.Read(header, 0 ,MAGIC_PKCS.Length);
            inF.Close();
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            
            if (header.SequenceEqual(MAGIC_PKCS))
            {
                _logger.LogDebug("Input file is DFIR-ORC (p7b / PKCS)");             
                DfirOrcDecryption orcDecrypt = new DfirOrcDecryption(_loggerDfirOrcDecryption);
                orcDecrypt.DecryptArchive(encryptedArchivePath, outputFolder, privateKeyPath, password: password);  
            }
            else
            {
                _logger.LogError("Unsupported archive format. This tool only decrypts DFIR-ORC .p7b archives.");
                return 0xA4;
            }
            stopwatch.Stop();
            _logger.LogDebug("Time spent: {Seconds} seconds", stopwatch.Elapsed.TotalSeconds);
            return 0;
            
        }
        catch (Exception ex)
        {
            _logger.LogError("Exception : {Message}", ex.Message);
            if (verbose)
            {
                _logger.LogDebug("Stack Trace : {StackTrace}", ex.StackTrace);
            }
            return -1;
        }
    }

    private static void ShowHelp()
    {
        Console.WriteLine($"OrcDecryptNet v{VERSION} - Decrypt DFIR-ORC (.p7b) archives");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  # Simple mode (using stored credentials):");
        Console.WriteLine("  OrcDecryptNet <archive_path> [output_folder] [-v|--verbose] [-h|--help]");
        Console.WriteLine();
        Console.WriteLine("  # Manual mode (without stored credentials):");
        Console.WriteLine("  OrcDecryptNet <archive_path> <output_folder> <private_key.pfx> [password] [-v|--verbose]");
        Console.WriteLine();
        Console.WriteLine("  # Credential management:");
        Console.WriteLine("  OrcDecryptNet --setup <private_key.pfx> [password] [-v|--verbose]");
        Console.WriteLine("  OrcDecryptNet --clear-credentials [-v|--verbose]");
        Console.WriteLine();
        Console.WriteLine("ARGUMENTS:");
        Console.WriteLine("  archive_path     Path to encrypted .p7b file");
        Console.WriteLine("  output_folder    Output directory (default: same as archive)");
        Console.WriteLine("  private_key.pfx  Private key file for decryption");
        Console.WriteLine("  password         Password for private key (optional)");
        Console.WriteLine();
        Console.WriteLine("OPTIONS:");
        Console.WriteLine("  -v, --verbose    Enable verbose logging");
        Console.WriteLine("  -h, --help       Show this help message");
        Console.WriteLine();
        Console.WriteLine("CREDENTIAL MANAGEMENT (Windows only):");
        Console.WriteLine("  --setup          Store private key and password securely (Windows DPAPI)");
        Console.WriteLine("  --clear-credentials  Remove stored credentials");
        Console.WriteLine();
        Console.WriteLine("  Note: Credential storage requires Windows DPAPI and is not available on Linux/macOS.");
        Console.WriteLine("        On non-Windows platforms, use manual mode with explicit key/password arguments.");
        Console.WriteLine();
        Console.WriteLine("EXAMPLES:");
        Console.WriteLine("  # First-time setup:");
        Console.WriteLine("  OrcDecryptNet --setup C:\\Keys\\private.pfx mypassword");
        Console.WriteLine();
        Console.WriteLine("  # Decrypt with stored credentials:");
        Console.WriteLine("  OrcDecryptNet C:\\Data\\archive.p7b");
        Console.WriteLine("  OrcDecryptNet C:\\Data\\archive.p7b C:\\Output");
        Console.WriteLine();
        Console.WriteLine("  # Manual decryption:");
        Console.WriteLine("  OrcDecryptNet archive.p7b output C:\\Keys\\private.pfx");
        Console.WriteLine();
        Console.WriteLine("  # With verbose logging:");
        Console.WriteLine("  OrcDecryptNet archive.p7b --verbose");
    }

    [SupportedOSPlatform("windows")]
    private static int HandleSetupCredentials(string[] args, CredentialStorage credentialStorage, bool verbose)
    {
        if (args.Length < 2)
        {
            if (verbose)
                _logger!.LogError("Usage: OrcDecryptNet --setup <private key .pfx> [password]");
            else
                Console.WriteLine("Error: Missing private key file path. Use --setup <private_key.pfx> [password]");
            return 0xA0;
        }

        string privateKeyPath = args[1];
        string password = args.Length > 2 ? args[2] : "";

        if (!File.Exists(privateKeyPath))
        {
            if (verbose)
                _logger!.LogError("Private key file not found: {PrivateKeyPath}", privateKeyPath);
            else
                Console.WriteLine($"Error: Private key file not found: {privateKeyPath}");
            return 0xA1;
        }

        if (string.IsNullOrEmpty(password))
        {
            Console.Write("Enter password for private key (or press Enter if none): ");
            password = ReadPassword();
        }

        try
        {
            var testKey = CommonCrypto.LoadPrivateKeyFromPfx(privateKeyPath, password);
            testKey?.Dispose();

            if (!OperatingSystem.IsWindows())
            {
                if (verbose)
                    _logger!.LogError("Credential storage is only supported on Windows (requires DPAPI)");
                else
                    Console.WriteLine("Error: Credential storage is only supported on Windows.");
                return 0xA0;
            }

            credentialStorage.StoreCredentials(privateKeyPath, password);
            if (verbose)
                _logger!.LogInformation("Credentials setup completed successfully");
            else
                Console.WriteLine("✓ Credentials setup completed successfully");
            return 0;
        }
        catch (Exception ex)
        {
            if (verbose)
                _logger!.LogError("Failed to setup credentials: {Message}", ex.Message);
            else
                Console.WriteLine($"Error: Failed to setup credentials: {ex.Message}");
            return 0xA2;
        }
    }

    [SupportedOSPlatform("windows")]
    private static CredentialStorage CreateCredentialStorage(ILogger<CredentialStorage> logger)
    {
        return new CredentialStorage(logger);
    }

    private static string ReadPassword()
    {
        var password = new StringBuilder();
        ConsoleKeyInfo key;

        do
        {
            key = Console.ReadKey(true);
            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        } while (key.Key != ConsoleKey.Enter);

        Console.WriteLine();
        return password.ToString();
    }
}

