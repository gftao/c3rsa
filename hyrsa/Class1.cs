using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
namespace hyrsa
{
    public class Class1
    {
        public class RSAUtil
        {

            public static void PEMConvertToXML(string strpem,string strxml)//PEM格式密钥转XML
            {
                AsymmetricCipherKeyPair keyPair;
                using (var sr = new StreamReader(strpem))
                {
                    var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                    keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                }
                var key = (RsaPrivateCrtKeyParameters)keyPair.Private;
                var p = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                    D = key.Exponent.ToByteArrayUnsigned(),
                    P = key.P.ToByteArrayUnsigned(),
                    Q = key.Q.ToByteArrayUnsigned(),
                    DP = key.DP.ToByteArrayUnsigned(),
                    DQ = key.DQ.ToByteArrayUnsigned(),
                    InverseQ = key.QInv.ToByteArrayUnsigned(),
                };
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(p);
                using (var sw = new StreamWriter(strxml))
                {
                    sw.Write(rsa.ToXmlString(true));
                }
            }

            public static void XMLConvertToPEM(string strpem, string strxml)//XML格式密钥转PEM
            {
                var rsa2 = new RSACryptoServiceProvider();
                using (var sr = new StreamReader(strxml))
                {
                    rsa2.FromXmlString(sr.ReadToEnd());
                }
                var p = rsa2.ExportParameters(true);

                var key = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, p.Modulus), new BigInteger(1, p.Exponent), new BigInteger(1, p.D),
                    new BigInteger(1, p.P), new BigInteger(1, p.Q), new BigInteger(1, p.DP), new BigInteger(1, p.DQ),
                    new BigInteger(1, p.InverseQ));

                using (var sw = new StreamWriter(strpem))
                {
                    var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                    pemWriter.WriteObject(key);
                }
            }


            public static bool Verify(String OriginalString, String SignatureString, String publicKeyPath)
            {
                  // 将base64签名数据转码为字节
                byte[] signedBase64 = Convert.FromBase64String(SignatureString);
                byte[] orgin = Encoding.UTF8.GetBytes(OriginalString);

                // X509Certificate2 x509_Cer1 = new X509Certificate2(publicKeyPath);

                StreamReader sr = new StreamReader(publicKeyPath, Encoding.Default);
                String line;
                string str = "";
                while ((line = sr.ReadLine()) != null)
                {
                    str += line.ToString();
                }

                RSACryptoServiceProvider oRSA = new RSACryptoServiceProvider();
                //oRSA.FromXmlString(x509_Cer1.PublicKey.Key.ToXmlString(false));
                oRSA.FromXmlString(str);

                bool bVerify = oRSA.VerifyData(orgin, "SHA1", signedBase64);
                return bVerify;

            }

            public static string RSASign(string data, string privateKeyPem)
            {
                RSACryptoServiceProvider rsaCsp = LoadCertificateFile(privateKeyPem);
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = rsaCsp.SignData(dataBytes, "SHA1");
                return Convert.ToBase64String(signatureBytes);
            }



            private static byte[] GetPem(string type, byte[] data)
            {
                string pem = Encoding.UTF8.GetString(data);
                string header = String.Format("-----BEGIN {0}-----\\n", type);
                string footer = String.Format("-----END {0}-----", type);
                int start = pem.IndexOf(header) + header.Length;
                int end = pem.IndexOf(footer, start);
                string base64 = pem.Substring(start, (end - start));
                return Convert.FromBase64String(base64);
            }

            private static RSACryptoServiceProvider LoadCertificateFile(string filename)
            {
                using (System.IO.FileStream fs = System.IO.File.OpenRead(filename))
                {
                    byte[] data = new byte[fs.Length];
                    byte[] res = null;
                    fs.Read(data, 0, data.Length);
                    if (data[0] != 0x30)
                    {
                        res = GetPem("RSA PRIVATE KEY", data);
                    }
                    try
                    {
                        RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(res);
                        return rsa;
                    }
                    catch (Exception ex)
                    {
                    }
                    return null;
                }
            }

            private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
            {
                byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

                // --------- Set up stream to decode the asn.1 encoded RSA private key ------
                MemoryStream mem = new MemoryStream(privkey);
                BinaryReader binr = new BinaryReader(mem);  //wrap Memory Stream with BinaryReader for easy reading
                byte bt = 0;
                ushort twobytes = 0;
                int elems = 0;
                try
                {
                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();    //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes != 0x0102) //version number
                        return null;
                    bt = binr.ReadByte();
                    if (bt != 0x00)
                        return null;


                    //------ all private key components are Integer sequences ----
                    elems = GetIntegerSize(binr);
                    MODULUS = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    E = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    D = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    P = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    Q = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DP = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DQ = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    IQ = binr.ReadBytes(elems);


                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    CspParameters CspParameters = new CspParameters();
                    CspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(1024, CspParameters);
                    RSAParameters RSAparams = new RSAParameters();
                    RSAparams.Modulus = MODULUS;
                    RSAparams.Exponent = E;
                    RSAparams.D = D;
                    RSAparams.P = P;
                    RSAparams.Q = Q;
                    RSAparams.DP = DP;
                    RSAparams.DQ = DQ;
                    RSAparams.InverseQ = IQ;
                    RSA.ImportParameters(RSAparams);
                    return RSA;
                }
                catch (Exception ex)
                {
                    return null;
                }
                finally
                {
                    binr.Close();
                }
            }

            private static int GetIntegerSize(BinaryReader binr)
            {
                byte bt = 0;
                byte lowbyte = 0x00;
                byte highbyte = 0x00;
                int count = 0;
                bt = binr.ReadByte();
                if (bt != 0x02)        //expect integer
                    return 0;
                bt = binr.ReadByte();

                if (bt == 0x81)
                    count = binr.ReadByte();    // data size in next byte
                else
                    if (bt == 0x82)
                {
                    highbyte = binr.ReadByte();    // data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;        // we already have the data size
                }

                while (binr.ReadByte() == 0x00)
                {    //remove high order zeros in data
                    count -= 1;
                }
                binr.BaseStream.Seek(-1, SeekOrigin.Current);        //last ReadByte wasn't a removed zero, so back up a byte
                return count;
            }
        }
    }
}
