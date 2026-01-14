using Microsoft.Extensions.Logging;

namespace OrcDecryptNet
{
    class DfirOrcUnstream(ILogger<DfirOrcUnstream> logger)
    {
        private readonly ILogger<DfirOrcUnstream> _logger = logger;
        
        const uint VERSION_JRNL = 2;
        public static readonly byte[] MAGIC_JRNL = { (byte)'J', (byte)'R', (byte)'N', (byte)'L' };
        static readonly byte[] MAGIC_WRITE = { (byte)'W', (byte)'R', (byte)'I', (byte)'T' };
        static readonly byte[] MAGIC_SEEK = { (byte)'S', (byte)'E', (byte)'E', (byte)'K' };
        static readonly byte[] MAGIC_CLOSE = { (byte)'C', (byte)'L', (byte)'O', (byte)'S' };

        public int DoUnstream(Stream fIn, Stream fOut)
        {
            fIn.Seek(0, SeekOrigin.Begin);

            byte[] headerBuffer = new byte[12]; // MAGIC (4 bytes) + Version (4 bytes)
            int bytesRead = fIn.Read(headerBuffer, 0, 8);
            if (bytesRead != 8 || !headerBuffer.AsSpan(0, 4).SequenceEqual(MAGIC_JRNL))
            {
                this._logger.LogDebug("Unstream: not a stream file, bad magic");
                return -1;
            }

            uint version = BitConverter.ToUInt32(headerBuffer, 4);
            if (version != VERSION_JRNL)
            {
                this._logger.LogDebug($"Unstream: unhandled JRNL version ({version:X}, but I know only {VERSION_JRNL:X})");
                return -1;
            }

            byte[] opBuffer = new byte[16];
            byte[] readBuffer = new byte[1024 * 1024];

            while (true)
            {
                bytesRead = fIn.Read(opBuffer, 0, 16);
                if (bytesRead != 16)
                {
                    this._logger.LogDebug("Unstream: cannot read stream opcode");
                    return -1;
                }

                ReadOnlySpan<byte> magic = opBuffer.AsSpan(0, 4);
                uint dw = BitConverter.ToUInt32(opBuffer, 4);
                ulong ull = BitConverter.ToUInt64(opBuffer, 8);

                if (magic.SequenceEqual(MAGIC_CLOSE))
                {
                    break;
                }
                else if (magic.SequenceEqual(MAGIC_SEEK))
                {
                    long offset = (long)ull;
                    SeekOrigin seekOrigin = dw switch
                    {
                        1 => SeekOrigin.Current,
                        2 => SeekOrigin.End,
                        _ => SeekOrigin.Begin
                    };
                    fOut.Seek(offset, seekOrigin);
                }
                else if (magic.SequenceEqual(MAGIC_WRITE))
                {
                    ulong remainingLen = ull;
                    while (remainingLen > 0)
                    {
                        int chunkSize = (int)Math.Min((ulong)readBuffer.Length, remainingLen);
                        bytesRead = fIn.Read(readBuffer, 0, chunkSize);
                        if (bytesRead <= 0)
                        {
                            this._logger.LogDebug("Unstream: cannot read data");
                            return -1;
                        }

                        fOut.Write(readBuffer, 0, bytesRead);
                        remainingLen -= (ulong)bytesRead;
                    }
                }
                else
                {
                    this._logger.LogDebug("Unstream: bad stream opcode");
                    return -1;
                }
            }

            return 0;
        }

    }
}