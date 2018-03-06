#region

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;

#endregion

namespace Tencent.Mars
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args == null) return;
            try
            {
                switch (args.Length)
                {
                    case 1:
                    {
                        var path = Path.GetFullPath(args[0]);
                        if (Directory.Exists(path))
                        {
                            foreach (var file in Directory.EnumerateFileSystemEntries(path, "*.xlog",
                                SearchOption.AllDirectories))
                                Decrypter.ParseFile(file,
                                    Path.Combine(Path.GetDirectoryName(file),
                                        $"{Path.GetFileNameWithoutExtension(file)}.log"));
                            return;
                        }

                        Decrypter.ParseFile(path,
                            Path.Combine(Path.GetDirectoryName(path),
                                $"{Path.GetFileNameWithoutExtension(path)}.log"));
                    }
                        break;
                    default:
                        foreach (var file in args.SelectMany(ParsePath).Where(path => !string.IsNullOrEmpty(path)))
                            Decrypter.ParseFile(file,
                                Path.Combine(Path.GetDirectoryName(file),
                                    $"{Path.GetFileNameWithoutExtension(file)}.log"));
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            Console.ReadKey();
        }

        private static IEnumerable<string> ParsePath(string path)
        {
            if (string.IsNullOrEmpty(path)) yield break;
            path = Path.GetFullPath(path);
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.EnumerateFileSystemEntries(path, "*.xlog", SearchOption.AllDirectories))
                    yield return file;
                yield break;
            }

            yield return path;
        }
    }
}