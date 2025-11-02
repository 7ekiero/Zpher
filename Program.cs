//<3P<3R<3I<3V<3A<3C<3Y<3<3M<3E<3A<3N<3S<3<3L<3I<3B<3E<3R<3T<3Y<3
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Zpher
{
    internal class Program
    {
        // Constantes
        private static readonly byte[] MAGIC = Encoding.ASCII.GetBytes("7KMVAUL7");
        private const byte VERSION = 0x01;
        private const byte KDF_ARGON2ID = 0xA2;
        private const int SALT_LEN = 16;
        private const int NONCE_LEN = 12;
        private const int TAG_LEN = 16;
        private const int FRAME_SIZE = 1 << 20; // 1 MiB

        private static void Main()
        {
            Console.Title = "Zpher 1.0";
            Console.OutputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n==[[   ZPHER ENCRYPTION TOOL   ]]==");
                Console.WriteLine("  ==   PRIVACY MEANS LIBERTY   ==  ");
                Console.ResetColor();

                Console.WriteLine("\n1) Cifrar");
                Console.WriteLine("2) Descifrar (.7km)");
                Console.WriteLine("3) Ayuda / Manual");
                Console.WriteLine("4) Salir\n");
                Console.Write("Selecciona una opción: ");

                var key = Console.ReadKey();
                Console.WriteLine();

                switch (key.KeyChar)
                {
                    case '1': MenuUnifiedEncrypt(); break;
                    case '2': MenuDecrypt(); break;
                    case '3': ShowManual(); break;
                    case '4': return;
                    default: Console.WriteLine("Opción no válida.\n"); break;
                }
            }
        }

        // ===== Manual / Ayuda =====
        private static void ShowManual()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("=== ZPHER MANUAL ===");
            Console.ResetColor();

            Console.WriteLine(@"
Zpher comprime (si es carpeta) y cifra con AES-GCM, derivando la clave con Argon2id.

FUNCIONAMIENTO
· Cifrar: archivo/carpeta → (ZIP si carpeta) → contenedor 7KMVAUL7 v1.
· Descifrar: valida integridad (tag) y contexto (cabecera + AAD) antes de escribir.

ELEMENTOS
· Contraseña → se deriva a clave con Argon2id (memoria 256MB, iter=3, hilos=CPU).
· Salt (16B), Nonce base (12B), Tag (16B por bloque).
· AAD (Associated Authenticated Data) → se autentica la **cabecera completa** + tu etiqueta.
  Si cualquier campo cambia, el descifrado falla.

CONSEJOS
1) Usa contraseñas largas/aleatorias 2) No re-cifres .7km 3) Guarda el .log
4) Sin contraseña correcta no hay recuperación

DISCLAIMER
Proyecto educativo creado para uso personal y con fines legales, no me hago responsable de un mal uso del mismo.


- 7ekiero <3
");
            Console.WriteLine("Pulsa una tecla para volver...");
            Console.ReadKey(true);
            Console.Clear();
        }

        // ===== Menú Cifrar unificado =====
        private static void MenuUnifiedEncrypt()
        {
            Console.Write("\nRuta (archivo o carpeta) a cifrar: ");
            string? input = Console.ReadLine()?.Trim('"');
            if (string.IsNullOrWhiteSpace(input))
            {
                Console.WriteLine("Ruta no válida.");
                return;
            }

            bool isFile = File.Exists(input);
            bool isDir = Directory.Exists(input);
            if (!isFile && !isDir)
            {
                Console.WriteLine("Ruta no encontrada.");
                return;
            }

            // Salida por defecto: mismo nombre + .7km
            string defaultOut = Path.Combine(
                Path.GetDirectoryName(input) ?? ".",
                Path.GetFileName(input) + ".7km"
            );
            Console.Write($"Ruta de salida (ENTER para usar {defaultOut}): ");
            string? outPath = Console.ReadLine()?.Trim('"');
            if (string.IsNullOrWhiteSpace(outPath)) outPath = defaultOut;
            if (!outPath.EndsWith(".7km", StringComparison.OrdinalIgnoreCase)) outPath += ".7km";

            Console.Write("Etiqueta (AAD opcional): ");
            string aad = Console.ReadLine() ?? "";

            string password;
            try
            {
                password = ReadPasswordConfirm();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
                return;
            }

            try
            {
                if (isDir)
                    EncryptFolder(input, outPath, password, aad);
                else
                    Encrypt(input, outPath, password, aad);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nArchivo cifrado correctamente: {outPath}");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally { Console.ResetColor(); }
        }

        // ===== Menú Descifrar =====
        private static void MenuDecrypt()
        {
            Console.Write("\nRuta del archivo .7km: ");
            string? inPath = Console.ReadLine()?.Trim('"');
            if (string.IsNullOrWhiteSpace(inPath) || !File.Exists(inPath))
            {
                Console.WriteLine("Archivo no encontrado.");
                return;
            }

            // Salida por defecto: mismo nombre + .zip
            string baseName = Path.GetFileNameWithoutExtension(inPath);
            string directory = Path.GetDirectoryName(inPath) ?? ".";
            string defaultOut = Path.Combine(directory, baseName + ".zip");

            Console.Write($"Ruta de salida (ENTER para usar {defaultOut}): ");
            string? outPath = Console.ReadLine()?.Trim('"');
            if (string.IsNullOrWhiteSpace(outPath)) outPath = defaultOut;
            if (!outPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) outPath += ".zip";

            Console.Write("Contraseña: ");
            string password = ReadPassword();

            try
            {
                Decrypt(inPath, outPath, password);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nArchivo descifrado correctamente: {outPath}");

                Console.Write("¿Extraer ZIP ahora? (s/N): ");
                var resp = Console.ReadLine();
                if (!string.IsNullOrEmpty(resp) && resp.Trim().ToLower().StartsWith("s"))
                {
                    string target = Path.Combine(
                        Path.GetDirectoryName(outPath) ?? ".",
                        Path.GetFileNameWithoutExtension(outPath)
                    );
                    try
                    {
                        ZipFile.ExtractToDirectory(outPath, target, true);
                        Console.WriteLine($"ZIP extraído en: {target}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error extrayendo ZIP: {ex.Message}");
                    }
                }
            }
            catch (CryptographicException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nContraseña incorrecta o archivo modificado.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally { Console.ResetColor(); }
        }

        // ===== Cifrado =====
        private static void Encrypt(string inPath, string outPath, string password, string aad)
        {
            if (new FileInfo(inPath).Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Aviso: el archivo de entrada está vacío.");
                Console.ResetColor();
            }

            int memKB = 256 * 1024;
            int iter = 3;
            int lanes = Math.Max(1, Environment.ProcessorCount);

            byte[] salt = RandomBytes(SALT_LEN);
            byte[] baseNonce = RandomBytes(NONCE_LEN);
            byte[] aadBytes = string.IsNullOrEmpty(aad) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(aad);

            // Cabecera exacta (se escribe y además se usa como AAD real)
            byte[] headerBytes = BuildHeaderBytes(salt, memKB, iter, lanes, baseNonce, aadBytes);
            byte[] key = DeriveKeyArgon2id(password, salt, memKB, iter, lanes, 32);

            var sw = Stopwatch.StartNew();

            using var inf = new FileStream(inPath, FileMode.Open, FileAccess.Read);
            using var outf = new FileStream(outPath, FileMode.Create, FileAccess.Write);

            // Escribir cabecera
            outf.Write(headerBytes);

            using var aesg = new AesGcm(key, TAG_LEN);
            byte[] plain = new byte[FRAME_SIZE];
            byte[] cipher = new byte[FRAME_SIZE];
            byte[] tag = new byte[TAG_LEN];

            long counter = 0;
            long total = inf.Length;
            long processed = 0;

            Console.WriteLine("\nCifrando...");

            // stackalloc fuera del bucle (evita CA2014)
            Span<byte> buf4 = stackalloc byte[4];

            int read;
            while ((read = inf.Read(plain, 0, FRAME_SIZE)) > 0)
            {
                byte[] nonce = DeriveNonce(baseNonce, counter++);
                aesg.Encrypt(nonce, plain.AsSpan(0, read), cipher.AsSpan(0, read), tag, headerBytes);

                BinaryPrimitives.WriteInt32LittleEndian(buf4, read);
                outf.Write(buf4);
                outf.Write(cipher, 0, read);
                outf.Write(tag);

                processed += read;
                ShowProgress(processed, total);
            }

            sw.Stop();

            Console.WriteLine();
            CryptographicOperations.ZeroMemory(key);
            Array.Clear(plain, 0, plain.Length);
            Array.Clear(cipher, 0, cipher.Length);
            Array.Clear(tag, 0, tag.Length);

            // Resumen técnico + log
            string report = BuildReport(outPath, salt, baseNonce, memKB, iter, lanes, aad, sw.Elapsed);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(report);
            Console.ResetColor();
            try { File.WriteAllText(outPath + ".log", report); } catch { }
        }

        // ===== Descifrado =====
        private static void Decrypt(string inPath, string outPath, string password)
        {
            using var inf = new FileStream(inPath, FileMode.Open, FileAccess.Read);
            using var outf = new FileStream(outPath, FileMode.Create, FileAccess.Write);

            byte[] header = ReadFullHeader(inf,
                                           out byte ver,
                                           out byte kdf,
                                           out byte[] salt,
                                           out int memKB,
                                           out int iter,
                                           out int lanes,
                                           out byte[] baseNonce,
                                           out byte[] aadBytes);

            if (ver != VERSION) throw new InvalidDataException("Versión no soportada.");
            if (kdf != KDF_ARGON2ID) throw new InvalidDataException("KDF no soportado.");

            byte[] key = DeriveKeyArgon2id(password, salt, memKB, iter, lanes, 32);

            using var aesg = new AesGcm(key, TAG_LEN);
            byte[] cipher = new byte[FRAME_SIZE];
            byte[] plain = new byte[FRAME_SIZE];
            byte[] tag = new byte[TAG_LEN];

            long counter = 0;
            long total = inf.Length;
            long processed = inf.Position;

            Console.WriteLine("\nDescifrando...");

            var sw = Stopwatch.StartNew();

            Span<byte> buf4 = stackalloc byte[4]; // fuera del bucle

            while (inf.Position < inf.Length)
            {
                if (inf.Read(buf4) != 4) break;
                int len = BinaryPrimitives.ReadInt32LittleEndian(buf4);
                if (len <= 0 || len > FRAME_SIZE) throw new InvalidDataException("Trama inválida.");

                inf.ReadExactly(cipher.AsSpan(0, len));
                inf.ReadExactly(tag);

                byte[] nonce = DeriveNonce(baseNonce, counter++);
                aesg.Decrypt(nonce, cipher.AsSpan(0, len), tag, plain.AsSpan(0, len), header);
                outf.Write(plain, 0, len);

                processed = inf.Position;
                ShowProgress(processed, total);
            }

            sw.Stop();

            Console.WriteLine();
            CryptographicOperations.ZeroMemory(key);
            Array.Clear(cipher, 0, cipher.Length);
            Array.Clear(plain, 0, plain.Length);
            Array.Clear(tag, 0, tag.Length);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"\n[OK] Descifrado completo en {sw.Elapsed.TotalSeconds:F2}s");
            Console.ResetColor();
        }

        // ===== Utils =====

        // Cabecera exacta (sirve también como AAD)
        private static byte[] BuildHeaderBytes(byte[] salt, int memKB, int iter, int lanes, byte[] baseNonce, byte[] aadBytes)
        {
            using var ms = new MemoryStream(8 + 1 + 1 + SALT_LEN + 4 + 4 + 4 + NONCE_LEN + 2 + aadBytes.Length);
            // MAGIC
            ms.Write(MAGIC, 0, MAGIC.Length);
            // VERSION + KDF
            ms.WriteByte(VERSION);
            ms.WriteByte(KDF_ARGON2ID);
            // salt
            ms.Write(salt, 0, salt.Length);
            // params
            Span<byte> b4 = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(b4, memKB); ms.Write(b4);
            BinaryPrimitives.WriteInt32LittleEndian(b4, iter); ms.Write(b4);
            BinaryPrimitives.WriteInt32LittleEndian(b4, lanes); ms.Write(b4);
            // nonce base
            ms.Write(baseNonce, 0, baseNonce.Length);
            // aad len + aad
            Span<byte> b2 = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(b2, (ushort)aadBytes.Length); ms.Write(b2);
            if (aadBytes.Length > 0) ms.Write(aadBytes, 0, aadBytes.Length);
            return ms.ToArray();
        }

        // Leer cabecera completa y reconstruirla para AAD
        private static byte[] ReadFullHeader(FileStream inf,
                                             out byte version,
                                             out byte kdf,
                                             out byte[] salt,
                                             out int memKB,
                                             out int iter,
                                             out int lanes,
                                             out byte[] baseNonce,
                                             out byte[] aadBytes)
        {
            Span<byte> magic = stackalloc byte[8];
            if (inf.Read(magic) != 8 || !magic.SequenceEqual(MAGIC))
                throw new InvalidDataException("Formato no reconocido.");

            version = (byte)inf.ReadByte();
            kdf = (byte)inf.ReadByte();

            salt = new byte[SALT_LEN];
            inf.ReadExactly(salt);

            Span<byte> b4 = stackalloc byte[4];
            inf.ReadExactly(b4); memKB = BinaryPrimitives.ReadInt32LittleEndian(b4);
            inf.ReadExactly(b4); iter = BinaryPrimitives.ReadInt32LittleEndian(b4);
            inf.ReadExactly(b4); lanes = BinaryPrimitives.ReadInt32LittleEndian(b4);

            baseNonce = new byte[NONCE_LEN];
            inf.ReadExactly(baseNonce);

            Span<byte> b2 = stackalloc byte[2];
            inf.ReadExactly(b2);
            int aadLen = BinaryPrimitives.ReadUInt16LittleEndian(b2);
            aadBytes = aadLen > 0 ? new byte[aadLen] : Array.Empty<byte>();
            if (aadLen > 0) inf.ReadExactly(aadBytes);

            return BuildHeaderBytes(salt, memKB, iter, lanes, baseNonce, aadBytes);
        }

        private static void EncryptFolder(string folderPath, string outEncPath, string password, string aad)
        {
            if (!Directory.Exists(folderPath)) throw new DirectoryNotFoundException("Carpeta no encontrada.");
            string tempZip = Path.Combine(Path.GetTempPath(), $"zpher_{Guid.NewGuid():N}.zip");

            try
            {
                ZipFile.CreateFromDirectory(folderPath, tempZip, CompressionLevel.Optimal, includeBaseDirectory: false);
                Encrypt(tempZip, outEncPath, password, aad);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nCarpeta comprimida y cifrada -> {outEncPath}");
            }
            finally
            {
                try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { }
                Console.ResetColor();
            }
        }

        private static void ShowProgress(long current, long total)
        {
            double percent = (double)current / Math.Max(1, total) * 100;
            Console.CursorLeft = 0;
            Console.Write($"Progreso: {percent,6:F2}%");
        }

        private static byte[] DeriveKeyArgon2id(string password, byte[] salt, int memKB, int iter, int lanes, int outLen)
        {
            var pwdBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                var argon = new Argon2id(pwdBytes)
                {
                    DegreeOfParallelism = Math.Max(1, lanes),
                    Iterations = iter,
                    MemorySize = memKB,
                    Salt = salt
                };
                return argon.GetBytes(outLen);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pwdBytes);
            }
        }

        private static byte[] DeriveNonce(byte[] baseNonce, long counter)
        {
            byte[] n = new byte[NONCE_LEN];
            Buffer.BlockCopy(baseNonce, 0, n, 0, NONCE_LEN);

            // stackalloc fuera de bucle
            Span<byte> ctr = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(ctr, (ulong)counter);

            for (int i = 0; i < ctr.Length && i < NONCE_LEN; i++)
                n[i] ^= ctr[i];

            return n;
        }

        private static byte[] RandomBytes(int len)
        {
            byte[] b = new byte[len];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        private static string ReadPassword()
        {
            var sb = new StringBuilder();
            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Length--;
                    Console.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        private static string ReadPasswordConfirm()
        {
            const int MAX_ATTEMPTS = 3;
            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)
            {
                Console.Write("Contraseña: ");
                string first = ReadPassword();

                if (string.IsNullOrWhiteSpace(first))
                {
                    Console.WriteLine("La contraseña no puede estar vacía.");
                    continue;
                }

                if (first.Length < 8)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Aviso: se recomienda usar al menos 8 caracteres.");
                    Console.ResetColor();
                }

                Console.Write("Repite la contraseña: ");
                string second = ReadPassword();

                if (first == second)
                {
                    PrintPasswordEntropy(first);
                    return first;
                }

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Las contraseñas no coinciden (intento {attempt}/{MAX_ATTEMPTS}).");
                Console.ResetColor();
            }
            throw new Exception("No se confirmó la contraseña. Operación cancelada.");
        }

        private static void PrintPasswordEntropy(string pwd)
        {
            int charset = 0;
            bool lower = false, upper = false, digit = false, symbol = false;
            foreach (char c in pwd)
            {
                if (char.IsLower(c)) lower = true;
                else if (char.IsUpper(c)) upper = true;
                else if (char.IsDigit(c)) digit = true;
                else symbol = true;
            }
            if (lower) charset += 26;
            if (upper) charset += 26;
            if (digit) charset += 10;
            if (symbol) charset += 32; // aprox. símbolos ASCII

            double bits = (charset > 0) ? (pwd.Length * Math.Log(charset, 2)) : 0.0;
            string rating = bits < 40 ? "Débil" : bits < 60 ? "Media" : bits < 80 ? "Alta" : "Excelente";

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"AVISO: Entropía estimada → {bits:F1} bits → {rating}");
            Console.WriteLine($"Se está generando tu archivo...");
            Console.ResetColor();
        }

        private static string BuildReport(string outPath, byte[] salt, byte[] baseNonce, int memKB, int iter, int lanes, string aad, TimeSpan elapsed)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"\n--- ZPHER REPORT ---");
            sb.AppendLine($"Salida: {outPath}");
            sb.AppendLine($"Formato: 7KMVAUL7 v{VERSION}");
            sb.AppendLine($"KDF: Argon2id | Memoria: {memKB} KB | Iteraciones: {iter} | Paralelismo: {lanes}");
            sb.AppendLine($"Salt: {BitConverter.ToString(salt).Replace("-", "")}");
            sb.AppendLine($"Nonce base: {BitConverter.ToString(baseNonce).Replace("-", "")}");
            sb.AppendLine($"AAD visible: {(string.IsNullOrEmpty(aad) ? "(vacío)" : aad)}");
            sb.AppendLine($"Cabecera autenticada: SÍ (header completo + AAD)");
            sb.AppendLine($"Tag por bloque: {TAG_LEN} bytes (AES-GCM)");
            sb.AppendLine($"-----------------------");
            sb.AppendLine($"7ekiero <3");
            return sb.ToString();
        }
    }
}

// Made with AI support.
// Privacy means liberty.
// Stay safe.
// 7ekiero <3
