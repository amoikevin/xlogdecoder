#region

using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using static System.Runtime.CompilerServices.MethodImplOptions;

#endregion

namespace Tencent.Mars
{
    public static class Decrypter
    {
        private const byte MAGIC_NO_COMPRESS_START = 0x03;
        private const byte MAGIC_NO_COMPRESS_START1 = 0x06;
        private const byte MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08;
        private const byte MAGIC_COMPRESS_START = 0x04;
        private const byte MAGIC_COMPRESS_START1 = 0x05;
        private const byte MAGIC_COMPRESS_START2 = 0x07;
        private const byte MAGIC_COMPRESS_NO_CRYPT_START = 0x09;

        private const string PrivKey = "145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8";

        private const string PubKey =
            "572d1e2710ae5fbca54c76a382fdd44050b3a675cb2bf39feebe85ef63d947aff0fa4943f1112e8b6af34bebebbaefa1a0aae055d9259b89a1858f7cc9af9df1";


        private const byte MAGIC_END = 0x00;

        private static ushort lastseq;

        private static int DecodeBuffer(byte[] buffer, int offset, BinaryWriter output)
        {
            if (offset >= buffer.Length) return -1;

            var ret = IsGoodLogBuffer(buffer, offset, 1);
            if (!ret.Item1)
            {
                var temp = Copy(buffer, offset, buffer.Length - offset);
                var fixpos = GetLogStartPos(temp, offset, 1);
                if (-1 == fixpos)
                    return -1;
                output.Write($"[F]decode_log_file.py decode error len={fixpos}, result:{ret.Item2}\n");
                offset += fixpos;
            }

            int cryptKeyLen;
            switch (buffer[offset])
            {
                case MAGIC_NO_COMPRESS_START:
                case MAGIC_COMPRESS_START:
                case MAGIC_COMPRESS_START1:
                    cryptKeyLen = 4;
                    break;
                case MAGIC_COMPRESS_START2:
                case MAGIC_NO_COMPRESS_START1:
                case MAGIC_NO_COMPRESS_NO_CRYPT_START:
                case MAGIC_COMPRESS_NO_CRYPT_START:
                    cryptKeyLen = 64;
                    break;
                default:
                    output.Write($"in DecodeBuffer _buffer[{offset}]:{buffer[offset]} != MAGIC_NUM_START");
                    return -1;
            }

            var headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;
            var bodyOffset = offset + headerLen;
            var length = ToInt32(buffer, bodyOffset - 4 - cryptKeyLen);
            var nextOffset = bodyOffset + length;

            var seq = ToUInt16(buffer, bodyOffset - 4 - cryptKeyLen - 2 - 2);

            if (seq != 0 && seq != 1 && lastseq != 0 && seq != lastseq + 1)
                output.Write($"[F]decode_log_file.py log seq:{lastseq + 1}-{seq - 1} is missing\n");

            if (seq != 0)
                lastseq = seq;

            //            var beginHour = (char) buffer[headerOffset - 4 - cryptKeyLen - 1 - 1];
            //            var endHour = (char) buffer[headerOffset - 4 - cryptKeyLen - 1];


            try
            {
                switch (buffer[offset])
                {
                    case MAGIC_COMPRESS_START:
                    case MAGIC_COMPRESS_NO_CRYPT_START:
                        using (var src = new MemoryStream(buffer, bodyOffset, length))
                        using (var deflate = new DeflateStream(src, CompressionMode.Decompress, false))
                        {
                            deflate.CopyTo(output.BaseStream);
                        }

                        break;
                    case MAGIC_COMPRESS_START1:
                        using (var src = new MemoryStream())
                        {
                            var index = bodyOffset;
                            var left = length;
                            while (left > 0)
                            {
                                var singleLogLen = ToUInt16(buffer, index);
                                src.Write(buffer, index + 2, singleLogLen);
                                var span = singleLogLen + 2;
                                index += span;
                                left -= span;
                            }

                            using (var deflate = new DeflateStream(src, CompressionMode.Decompress, false))
                            {
                                deflate.CopyTo(output.BaseStream);
                            }
                        }

                        break;
                    case MAGIC_COMPRESS_START2:
                        throw new NotImplementedException();

                        var k = new byte[4];
                        var num = length / (8 * 8);
                        for (var i = 0; i < num; i++) Decrypt(buffer, num, k);

                        using (var src = new MemoryStream(buffer, bodyOffset, length))
                        using (var deflate = new DeflateStream(src, CompressionMode.Decompress, false))
                        {
                            deflate.CopyTo(output.BaseStream);
                        }

                        break;
                    default:
                        output.Write(buffer, bodyOffset, length);
                        break;
                }
            }
            catch (Exception e)
            {
                output.Write($"[F]decode_log_file.py decompress err, {e}\n");
            }

            return nextOffset + 1;
        }

        private static void Decrypt(byte[] v, int offset, byte[] k)
        {
            const uint delta = 0x9E3779B9U;
            const uint op = 0xFFFFFFFFU;
            var sum = 0xE3779B90U;

            var v0 = ToUInt32(v, offset);
            var v1 = ToUInt32(v, offset + 4);

            var k0 = ToUInt32(k);
            var k1 = ToUInt32(k, 4);
            var k2 = ToUInt32(k, 8);
            var k3 = ToUInt32(k, 12);

            for (var i = 0; i < 32; i++)
            {
                v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3))) & op;
                v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1))) & op;
                sum = (sum - delta) & op;
            }

            Set(v, v0, offset);
            Set(v, v1, offset + 4);
        }

        private static int GetLogStartPos(byte[] buffer, int offset, int count)
        {
            while (offset < buffer.Length)
            {
                if ((MAGIC_NO_COMPRESS_START == buffer[offset] ||
                     MAGIC_NO_COMPRESS_START1 == buffer[offset] ||
                     MAGIC_COMPRESS_START == buffer[offset] ||
                     MAGIC_COMPRESS_START1 == buffer[offset] ||
                     MAGIC_COMPRESS_START2 == buffer[offset] ||
                     MAGIC_COMPRESS_NO_CRYPT_START == buffer[offset] ||
                     MAGIC_NO_COMPRESS_NO_CRYPT_START == buffer[offset]) &&
                    IsGoodLogBuffer(buffer, offset, count).Item1)
                    return offset;
                ++offset;
            }

            return -1;
        }


        private static (bool, string) IsGoodLogBuffer(byte[] buffer, int offset, int count)
        {
            if (offset == buffer.Length) return (true, "");

            int cryptKeyLen;
            switch (buffer[offset])
            {
                case MAGIC_NO_COMPRESS_START:
                case MAGIC_COMPRESS_START:
                case MAGIC_COMPRESS_START1:
                    cryptKeyLen = 4;
                    break;
                case MAGIC_COMPRESS_START2:
                case MAGIC_NO_COMPRESS_START1:
                case MAGIC_NO_COMPRESS_NO_CRYPT_START:
                case MAGIC_COMPRESS_NO_CRYPT_START:
                    cryptKeyLen = 64;
                    break;
                default:
                    return (false, $"_buffer[{offset}]:{buffer[offset]} != MAGIC_NUM_START");
            }

            var headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;
            var bodyOffset = offset + headerLen;
            if (bodyOffset + 1 + 1 > buffer.Length)
                return (false, $"offset:{offset} > len(buffer):{buffer.Length}");

            var length = ToInt32(buffer, bodyOffset - 4 - cryptKeyLen);
            var nextOffset = bodyOffset + length;

            if (nextOffset + 1 > buffer.Length)
                return (false,
                    $"log length:{length}, end pos {nextOffset + 1} > len(buffer):{buffer.Length}");

            if (MAGIC_END != buffer[nextOffset])
                return (false,
                    $"log length:{length}, buffer[{nextOffset}]:{buffer[nextOffset]} != MAGIC_END"
                    );

            return 1 >= count
                ? (true, "")
                : IsGoodLogBuffer(buffer, nextOffset + 1, count - 1);
        }

        public static void ParseFile(string input, string output)
        {
            var buffer = File.ReadAllBytes(input);
            var startPos = GetLogStartPos(buffer, 0, 2);
            if (-1 == startPos)
                return;

            using (var writer = new BinaryWriter(File.OpenWrite(output)))
            {
                while ((startPos = DecodeBuffer(buffer, startPos, writer)) != -1)
                {
                }
            }
        }

        #region Bytes Ext

        [MethodImpl(AggressiveInlining)]
        public static ushort ToUInt16(this byte[] buffer, int index = 0)
        {
            return (ushort) ((buffer[index + 1] << 8) |
                             buffer[index]);
        }

        [MethodImpl(AggressiveInlining)]
        public static int ToInt32(this byte[] buffer, int index = 0)
        {
            return (buffer[index + 3] << 24) |
                   (buffer[index + 2] << 16) |
                   (buffer[index + 1] << 8) |
                   buffer[index];
        }

        [MethodImpl(AggressiveInlining)]
        public static uint ToUInt32(this byte[] buffer, int index = 0)
        {
            return (uint) ((buffer[index + 3] << 24) |
                           (buffer[index + 2] << 16) |
                           (buffer[index + 1] << 8) |
                           buffer[index]);
        }


        [MethodImpl(AggressiveInlining)]
        public static void Set(this byte[] bytes, uint value, int index = 0)
        {
            bytes[index] = (byte) (value & 0xFF);
            bytes[index + 1] = (byte) ((value >> 8) & 0xFF);
            bytes[index + 2] = (byte) ((value >> 16) & 0xFF);
            bytes[index + 3] = (byte) ((value >> 24) & 0xFF);
        }

        [MethodImpl(AggressiveInlining)]
        public static T[] Copy<T>(this T[] src, int index, int length)
        {
            var dest = new T[length];
            Array.Copy(src, index, dest, 0, length);
            return dest;
        }

        #endregion
    }
}