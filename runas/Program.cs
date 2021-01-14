#define PDF_SIGNATURE_ENABLED
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
//using System.Runtime.InteropServices;

using System.ComponentModel;
using System.Data;
using System.Drawing;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

using System.Data.SqlClient;
using System.Threading;
using System.Net;
using System.Data.OleDb;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security;

using CryptoPro.Sharpei;
using iTextSharp.text.pdf;

using System.Security.Cryptography.Pkcs;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;
using RestSharp;
using iTextSharp.text.pdf.security;

#if PDF_SIGNATURE_ENABLED
namespace runasSignPDF_GOST
{


    public class Program
    {
        [STAThread]

        public static void Main(string[] args)
        {
            if (args.Length == 0) return;
            string document = args[0];


            ////////////////////////////////////////
            /// Открепленная подпись
            //signedPDF_detouched(document);
            ////////////////////////////////////////


            ////////////////////////////////////////
            /// Открепленная подпись 2
            signedPDF_detouched2(document);
            ////////////////////////////////////////

            // Интергрированная
           // signPDF(document);

            // UploadMultipart(document, new string[] { @"C:\TEMP\commonInfo.json", @"C:\TEMP\letter.pdf", @"C:\TEMP\letter.pdf.sig" }, new string[] { "commonInfo", "letter.pdf", "letter.pdf.sig" }, new string[] { "application/json", "application/octet-stream", "application/octet-stream" });
            //            HttpUpload_multi_Files(document, new string[] { @"C:\TEMP\commonInfo.json", @"C:\TEMP\letter.pdf", @"C:\TEMP\letter.pdf.sig" }, new string[] { "commonInfo", "letter.pdf", "letter.pdf.sig" }, new string[] { "application/json", "application/octet-stream", "application/octet-stream" });
            // HttpUpload_multi_Files(document, new string[] { @"C:\TEMP\commonInfo.json" }, new string[] { "commonInfo" }, new string[] { "application/json" });

            Console.In.Read();
        }






        public static void UploadMultipart(string url, string[] file, string[] filename, string[] contentType)
        {
            var webClient = new WebClient();
            string boundary = "------------------------" + DateTime.Now.Ticks.ToString("x");
            webClient.Headers.Add("Content-Type", "multipart/form-data; Boundary=" + boundary);
            webClient.Headers.Add("Authorization: Basic MTA3MTplNGRiNTg0Yy04ZjNlLTQzY2YtYjY2Ny02MWQyMjdhYzk1YjE=");

            // string package = string.Empty;
            string fileData = string.Empty;
            for (int i = 0; i < file.Count(); i++)
            {
                //  FileStream fileStream = new FileStream(file[i], FileMode.Open, FileAccess.Read);
                //  byte[] buffer = new byte[fileStream.Length];

                //       fileData += string.Format("{0}\r\nContent-Disposition: form-data; name=\"{1}\"; filename=\"{3}\"\r\nContent-Type: {2}\r\n\r\n{3}\r\n", boundary, filename[i], contentType[i], file[i]);
                fileData += string.Format("{0}\r\nContent-Disposition: form-data; name=\"{1}\"; \r\nContent-Type: {2}\r\n\r\n{3}\r\n", boundary, filename[i], contentType[i], file[i]);
                fileData += file[i] + "\r\n";

                /*
                int bytesRead = 0;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    fileData += webClient.Encoding.GetString(buffer);

                }

                */






            }


            fileData += boundary + "--\r\n";



            var nfile = webClient.Encoding.GetBytes(fileData);




            try
            {
                byte[] resp = webClient.UploadData(url, "POST", nfile);
                Console.Out.Write(webClient.Encoding.GetString(resp));
            }
            catch (Exception ex)
            {
                Console.Out.Write(ex.Message);
            }

        }


        static void signedPDF_detouched2(string document)
        {


            //string certificate_dn = "C=RU, S=lenobl, L=spb, O=fil, OU=IT, CN=iks, E=iks@iks";  // Subject->Name

            //  string certificate_dn = "L=Санкт-Петербург, O=ООО Филберт, CN=iks, E=kirill_host@mail.ru";
            /*
                        string certificate_dn = "ОГРН=1107847250961, СНИЛС=11635484352, ИНН=007841430420, E=n.fedorova@filbert.pro, O=ООО \"ФИЛБЕРТ\", T=Ведущий специалист, CN=ООО \"ФИЛБЕРТ\", " +
                            "SN=Федорова, G=Надежда Александровна, C=RU, L=САНКТ-ПЕТЕРБУРГ, S=78 ГОРОД САНКТ-ПЕТЕРБУРГ, STREET=УЛИЦА МАРШАЛА ГОВОРОВА, ДОМ 35, КОРПУС 5, ЛИТ. Ж";


            */

            string certificate_dn = "5A4075D2A0AB688A22720C0C22A16CAD6565DE55"; //"‎01f7f2f000faab2f9b4423fad021e40f58";

          //  byte [] certificate_dn =  ASCIIEncoding.ASCII.GetBytes(ser);
            //{‎01, 0xf7, 0xf2, 0xf0, 0x00, 0xfa, 0xab, 0x2f, 0x9b, 0x44, 0x23, 0xfa, 0xd0, 0x21, 0xe4, 0x0f, 0x58 };









            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection found = store.Certificates.Find(
                // X509FindType.FindBySubjectDistinguishedName, certificate_dn, true);
            X509FindType.FindByThumbprint, certificate_dn, validOnly: false);

            if (found.Count == 0)
            {

                Console.Out.Write("Сертфикат [" + certificate_dn + "] не найден ");
                return;
            }

            if (found.Count > 1)
            {
                Console.WriteLine("Найдено более одного секретного ключа.");
                return;
            }



            X509Certificate2 certificate = found[0];

            CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider cert_key = certificate.PrivateKey as CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider;


            var cspParameters = new CspParameters();
            //копируем параметры csp из исходного контекста сертификата
            cspParameters.KeyContainerName = cert_key.CspKeyContainerInfo.KeyContainerName;
            cspParameters.ProviderType = cert_key.CspKeyContainerInfo.ProviderType;
            cspParameters.ProviderName = cert_key.CspKeyContainerInfo.ProviderName;
            cspParameters.Flags = cert_key.CspKeyContainerInfo.MachineKeyStore
                              ? (CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore)
                              : (CspProviderFlags.UseExistingKey);
            cspParameters.KeyPassword = new SecureString();
            string pass = "12345678";                    // "zZ123123";
            foreach (var c in pass)
            {
                cspParameters.KeyPassword.AppendChar(c);
            }
            //создаем новый контекст сертификат, поскольку исходный открыт readonly
            certificate = new X509Certificate2(certificate.RawData);
            //задаем криптопровайдер с установленным паролем
            certificate.PrivateKey = new CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider(cspParameters);


            /////////////////////////читаем файл
            
                        System.IO.StreamReader file = new System.IO.StreamReader(document);



            var bytes = default(byte[]);
            using (var memstream = new MemoryStream())
            {
                file.BaseStream.CopyTo(memstream);
                bytes = memstream.ToArray();
            }


            

/*
            //  Переводим исходное сообщение в массив байтов.
            Encoding unicode = Encoding.Unicode;
            byte[] msgBytes = unicode.GetBytes(string.Empty);
*/


            /////////////////////////////   PDF  подпись ////////////////////////////////////////////////










            //  Создаем объект ContentInfo по сообщению.
            //  Это необходимо для создания объекта SignedCms.
            ContentInfo contentInfo = new ContentInfo(bytes);

            //  Создаем объект SignedCms по только что созданному
            //  объекту ContentInfo.
            //  SubjectIdentifierType установлен по умолчанию в 
            //  IssuerAndSerialNumber.
            //  Свойство Detached устанавливаем явно в true, таким 
            //  образом сообщение будет отделено от подписи.
            SignedCms signedCms = new SignedCms(contentInfo, true);

            //  Определяем подписывающего, объектом CmsSigner.
            CmsSigner cmsSigner = new CmsSigner(certificate);

            //  Подписываем CMS/PKCS #7 сообение.
            Console.Write("Вычисляем подпись сообщения для субъекта " +
                "{0} ... ", certificate.SubjectName.Name);
            signedCms.ComputeSignature(cmsSigner);
            Console.WriteLine("Успешно.");

            //  Кодируем CMS/PKCS #7 подпись сообщения.
            byte[] signDetouched = signedCms.Encode();


            string newSigned = Path.Combine(Path.GetDirectoryName(document) + @"\" + Path.GetFileNameWithoutExtension(document) + "_signed_Detouched2.sig");


            // using (var fs = new FileStream(newSigned, FileMode.Create, FileAccess.ReadWrite))
            FileStream fs = new FileStream(newSigned, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);

            fs.Write(signDetouched, 0, signDetouched.Length);

            fs.Close();




            /*
            FileStream fs1 = File.Create(newSigned);
            fs1.Close();
            StreamWriter FS = new StreamWriter("./data.ns");
            */










        }



        static void signedPDF_detouched(string document)
        {


            //string certificate_dn = "C=RU, S=lenobl, L=spb, O=fil, OU=IT, CN=iks, E=iks@iks";  // Subject->Name

            string certificate_dn = "L=Санкт-Петербург, O=ООО Филберт, CN=iks, E=kirill_host@mail.ru";



            X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName, certificate_dn, true);


            if (found.Count == 0)
            {

                Console.Out.Write("Сертфикат [" + certificate_dn + "] не найден ");
                return;
            }

            if (found.Count > 1)
            {
                Console.WriteLine("Найдено более одного секретного ключа.");
                return;
            }



            X509Certificate2 certificate = found[0];

            CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider cert_key = certificate.PrivateKey as CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider;


            var cspParameters = new CspParameters();
            //копируем параметры csp из исходного контекста сертификата
            cspParameters.KeyContainerName = cert_key.CspKeyContainerInfo.KeyContainerName;
            cspParameters.ProviderType = cert_key.CspKeyContainerInfo.ProviderType;
            cspParameters.ProviderName = cert_key.CspKeyContainerInfo.ProviderName;
            cspParameters.Flags = cert_key.CspKeyContainerInfo.MachineKeyStore
                              ? (CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore)
                              : (CspProviderFlags.UseExistingKey);
            cspParameters.KeyPassword = new SecureString();
            string pass = "zZ123123";
            foreach (var c in pass)
            {
                cspParameters.KeyPassword.AppendChar(c);
            }
            //создаем новый контекст сертификат, поскольку исходный открыт readonly
            certificate = new X509Certificate2(certificate.RawData);
            //задаем криптопровайдер с установленным паролем
            certificate.PrivateKey = new CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider(cspParameters);


            /////////////////////////читаем файл
            /*
                        System.IO.StreamReader file = new System.IO.StreamReader("C:\\TEMP\\test.json");

                        string s = file.ReadToEnd();
                              byte[] body = Encoding.Default.GetBytes(s);
            */


            /////////////////////////////   PDF  подпись ////////////////////////////////////////////////

            PdfReader reader = new PdfReader(document);


            string newSigned = Path.Combine(Path.GetDirectoryName(document) + @"\" + Path.GetFileNameWithoutExtension(document) + "_signed_.pdf" );

            FileStream signedPDF = new FileStream(newSigned, FileMode.Create, FileAccess.ReadWrite);
            PdfStamper st = PdfStamper.CreateSignature(reader, signedPDF, '\0', null, true);
            PdfSignatureAppearance sap = st.SignatureAppearance;









            //  Создаем объект ContentInfo по сообщению.
            //  Это необходимо для создания объекта SignedCms.
            ContentInfo contentInfo = new ContentInfo(reader.Metadata);

            //  Создаем объект SignedCms по только что созданному
            //  объекту ContentInfo.
            //  SubjectIdentifierType установлен по умолчанию в 
            //  IssuerAndSerialNumber.
            //  Свойство Detached устанавливаем явно в true, таким 
            //  образом сообщение будет отделено от подписи.
            SignedCms signedCms = new SignedCms(contentInfo, true);

            //  Определяем подписывающего, объектом CmsSigner.
            CmsSigner cmsSigner = new CmsSigner(certificate);

            //  Подписываем CMS/PKCS #7 сообение.
            Console.Write("Вычисляем подпись сообщения для субъекта " +
                "{0} ... ", certificate.SubjectName.Name);
            signedCms.ComputeSignature(cmsSigner);
            Console.WriteLine("Успешно.");

            //  Кодируем CMS/PKCS #7 подпись сообщения.
            byte [] signDetouched =  signedCms.Encode();


            newSigned = Path.Combine(Path.GetDirectoryName(document) + @"\" + Path.GetFileNameWithoutExtension(document) + "_signed_Detouched.sig");


            // using (var fs = new FileStream(newSigned, FileMode.Create, FileAccess.ReadWrite))
            FileStream fs = new FileStream(newSigned, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                 
                     fs.Write(signDetouched, 0, signDetouched.Length);

                     fs.Close();
                 
            

             
            /*
            FileStream fs1 = File.Create(newSigned);
            fs1.Close();
            StreamWriter FS = new StreamWriter("./data.ns");
            */










        }








        static void signPDF(string document)
        {




            //string certificate_dn = "C=RU, S=lenobl, L=spb, O=fil, OU=IT, CN=iks, E=iks@iks";  // Subject->Name

            string certificate_dn = "L=Санкт-Петербург, O=ООО Филберт, CN=iks, E=kirill_host@mail.ru";



            X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName, certificate_dn, true);


            if (found.Count==0)
            {

                Console.Out.Write("Сертфикат [" + certificate_dn + "] не найден ");
                return;
            }

            if (found.Count > 1)
            {
                Console.WriteLine("Найдено более одного секретного ключа.");
                return ;
            }


            
            X509Certificate2 certificate = found[0];

            CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider cert_key = certificate.PrivateKey as CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider;


            var cspParameters = new CspParameters();
            //копируем параметры csp из исходного контекста сертификата
            cspParameters.KeyContainerName = cert_key.CspKeyContainerInfo.KeyContainerName;
            cspParameters.ProviderType = cert_key.CspKeyContainerInfo.ProviderType;
            cspParameters.ProviderName = cert_key.CspKeyContainerInfo.ProviderName;
            cspParameters.Flags = cert_key.CspKeyContainerInfo.MachineKeyStore
                              ? (CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore)
                              : (CspProviderFlags.UseExistingKey);
            cspParameters.KeyPassword = new SecureString();
            string pass = "zZ123123";
            foreach (var c in pass)
            {
                cspParameters.KeyPassword.AppendChar(c);
            }
            //создаем новый контекст сертификат, поскольку исходный открыт readonly
            certificate = new X509Certificate2(certificate.RawData);
            //задаем криптопровайдер с установленным паролем
            certificate.PrivateKey = new CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider(cspParameters);


            /////////////////////////читаем файл
            /*
                        System.IO.StreamReader file = new System.IO.StreamReader("C:\\TEMP\\test.json");

                        string s = file.ReadToEnd();
                              byte[] body = Encoding.Default.GetBytes(s);
            */


            /////////////////////////////   PDF  подпись ////////////////////////////////////////////////

            PdfReader reader = new PdfReader(document);


            string newSigned = Path.Combine(Path.GetDirectoryName(document) + @"\" + Path.GetFileNameWithoutExtension(document) + "_signed" + Path.GetExtension(document));

            FileStream signedPDF = new FileStream(newSigned, FileMode.Create, FileAccess.ReadWrite);
            PdfStamper st = PdfStamper.CreateSignature(reader,signedPDF , '\0',null,true);
            PdfSignatureAppearance sap = st.SignatureAppearance;


           


            // Загружаем сертификат в объект iTextSharp
            X509CertificateParser parser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] {
                parser.ReadCertificate(certificate.RawData)
            };

            sap.Certificate = parser.ReadCertificate(certificate.RawData);
            sap.Reason = "I like to sign";
            sap.Location = "Universe";
            sap.Acro6Layers = true;

            //sap.Render = PdfSignatureAppearance.SignatureRender.NameAndDescription;
            sap.SignDate = DateTime.Now;

            // Выбираем подходящий тип фильтра
            PdfName filterName = new PdfName("CryptoPro PDF");

            // Создаем подпись
            PdfSignature dic = new PdfSignature(filterName, PdfName.ADBE_PKCS7_DETACHED);
            dic.Date = new PdfDate(sap.SignDate);
            dic.Name = "iks";
            if (sap.Reason != null)
                dic.Reason = sap.Reason;
            if (sap.Location != null)
                dic.Location = sap.Location;
            sap.CryptoDictionary = dic;

            int intCSize = 4000;
            Dictionary<PdfName, int> hashtable = new Dictionary<PdfName, int>();
            hashtable[PdfName.CONTENTS] = intCSize * 2 + 2;
            sap.PreClose(hashtable);
            Stream s = sap.GetRangeStream();
            MemoryStream ss = new MemoryStream();
            int read = 0;
            byte[] buff = new byte[8192];
            while ((read = s.Read(buff, 0, 8192)) > 0)
            {
                ss.Write(buff, 0, read);
            }




            //////////////////////////////////////////





            // Вычисляем подпись
            ContentInfo contentInfo = new ContentInfo(ss.ToArray());
            SignedCms signedCms = new SignedCms(contentInfo, true);
            CmsSigner cmsSigner = new CmsSigner(certificate);
            signedCms.ComputeSignature(cmsSigner, false);
            byte[] pk = signedCms.Encode();


            /*
            // Помещаем подпись в документ
            byte[] outc = new byte[intCSize];
            PdfDictionary dic2 = new PdfDictionary();
            Array.Copy(pk, 0, outc, 0, pk.Length);
            dic2.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));
            sap.Close(dic2);
            */


            Console.WriteLine(string.Format("Документ {0} успешно подписан на ключе {1} => {2}.",
                document, certificate.Subject, newSigned));

            /*
            System.IO.StreamWriter sw = null;
            System.IO.FileStream fs = new System.IO.FileStream("C:\\TEMP\\test_json_signed.json", System.IO.FileMode.Append, System.IO.FileAccess.Write);
            

            sw = new System.IO.StreamWriter(fs, Encoding.GetEncoding(1251));
            sw.WriteLine(Encoding.Default.GetString(pk));
            sw.Close();

            fs.Dispose();
            fs.Close();
            */


            // Помещаем подпись в документ
            byte[] outc = new byte[intCSize];
            PdfDictionary dic2 = new PdfDictionary();
            Array.Copy(pk, 0, outc, 0, pk.Length);
            dic2.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));
            sap.Close(dic2);











            /////////////////////////////////////////////////////////////////////////////


        }






        /// <summary>
        /// ////////////////////////////////////////////////////////////////////// Test run ////////////////////////////////////////////////////////////////////////////
        /// </summary>
        /// <param name="args"></param>
        void r_u_n(string[] args)
        {
            Console.WriteLine("Running...");
            if (args.Count() == 0) return;


            System.Security.SecureString a = new System.Security.SecureString();

            a.AppendChar('P');
            a.AppendChar('r');
            a.AppendChar('i');
            a.AppendChar('e');
            a.AppendChar('s');
            a.AppendChar('t'); a.AppendChar('1'); a.AppendChar('.'); a.AppendChar('*'); a.AppendChar('#');



            // Configure the process using the StartInfo properties.
            ProcessStartInfo startInfo = new ProcessStartInfo();

            startInfo.CreateNoWindow = false;

            startInfo.FileName = "c:\\windows\\system32\\xcopy";
            //startInfo.FileName = @"C:\TEMP\t.cmd";
            string str1 = args[0];
            string str2 = args[1];
            startInfo.Arguments = "\"" + str1 + "\"" + " " + "\"" + str2 + "\"";
            // startInfo.Arguments = @">c:\temp\test" ;
            // process.StartInfo.WindowStyle = ProcessWindowStyle.Maximized;


            startInfo.WorkingDirectory = @"c:\temp";
            startInfo.LoadUserProfile = true;
            startInfo.Password = a;
            startInfo.Domain = "ctr-pr";
            startInfo.UserName = "ilinks";
            startInfo.UseShellExecute = false;


            using (Process exeProcess = Process.Start(startInfo))

            {

                exeProcess.WaitForExit(1000);

            }

            //Process.Start(@"c:\windows\system32\cmd.exe", "ilinks",a, "ctr-pr");

        }
        //                 "O:\5. Обмен информацией между подразделениями\5.07. От УИТ\5.07.02. Для УД" 





        public static void HttpUpload_multi_Files(string url, string[] file, string[] paramName, string[] contentType)
        {

            int Dlina = 0;
            //log.Debug(string.Format("Uploading {0} to {1}", file, url));
            string boundary = String.Format("--------------------------{0:N}", Guid.NewGuid());


            //         string boundary = @"--------------------------" + DateTime.Now.Ticks.ToString("x").PadRight(16,'0');
            byte[] boundarybytes = System.Text.Encoding.ASCII.GetBytes(boundary);

            HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(url);
            /*
                        foreach (string key in headerItems.Keys)
                        {
                            if (key == "Referer")
                            {
                                wr.Referer = headerItems[key];
                            }
                            else
                            {
                                wr.Headers.Add(key, headerItems[key]);
                            }
                        }
                        */
            wr.UserAgent = "myApp";
            wr.Accept = "*/*";
            wr.ContentType = @"multipart/form-data; boundary=" + boundary;
            wr.Method = "POST";
            //wr.ContentLength = 2562;
            //   wr.Expect = "100-continue";
            //   wr.KeepAlive = true;
            //  wr.Credentials = System.Net.CredentialCache.DefaultCredentials;

            Uri uri = new Uri(url);
            wr.Host = uri.Host;
            WebHeaderCollection myWebHeaderCollection = wr.Headers;

            //   wr.Referer = textBox2.Text;

            myWebHeaderCollection.Add("Authorization: Basic MTA3MTplNGRiNTg0Yy04ZjNlLTQzY2YtYjY2Ny02MWQyMjdhYzk1YjE=");
            // wr.Headers.Add("User-Agent: \"curl/7.68.0\"");

            Stream rs = wr.GetRequestStream();

            ///////////////////////////////////////////////////////////////////////////////form text///////////////////////////////////////////////////////////
            /*
               rs.Write(boundarybytes, 0, boundarybytes.Length);
               test += boundary;

               string formdata = "\r\nContent-Disposition: form-data; name=\"form\"\r\n\r\n";
               byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formdata);
               rs.Write(formitembytes,0, formitembytes.Length);
               test += formdata;

               string form = "\"{0}\":\"{1}\",\r\n";

               for (int i = 0; i < file.Count(); i++)
               {



                       string f = string.Format(form, paramName[i], file[i]);
                   byte[] fbytes = System.Text.Encoding.UTF8.GetBytes(f);
                   rs.Write(fbytes, 0, f.Length);
                   test += f;
               }
              */
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


            //  rs.Write(System.Text.Encoding.UTF8.GetBytes("\r\n"),0,2);
            rs.Write(boundarybytes, 0, boundarybytes.Length);
            Dlina += boundarybytes.Length;

            string headerTemplate = Environment.NewLine + @"Content-Disposition: form-data; name=""{0}""; filename=""{2}""" + Environment.NewLine + "Content-Type: {1}" + Environment.NewLine + Environment.NewLine;
            string header = string.Empty;

            for (int i = 0; i < file.Count(); i++)
            {
                header = string.Format(headerTemplate, paramName[i], contentType[i], Path.GetFileName(file[i]));
                byte[] headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
                rs.Write(headerbytes, 0, headerbytes.Length);
                Dlina += headerbytes.Length;
                FileStream fileStream = new FileStream(file[i], FileMode.Open, FileAccess.Read);

                byte[] buffer = new byte[fileStream.Length];
                int bytesRead = 0;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    rs.Write(buffer, 0, bytesRead);
                    Dlina += bytesRead;


                }
                fileStream.Close();
                byte[] NewS = System.Text.Encoding.UTF8.GetBytes(Environment.NewLine);
                rs.Write(NewS, 0, NewS.Length);
                Dlina += NewS.Length;
                // test += "\r\n";
                rs.Write(boundarybytes, 0, boundarybytes.Length);
                Dlina += boundarybytes.Length;


            }

            byte[] trailer = System.Text.Encoding.ASCII.GetBytes("--" + Environment.NewLine);
            rs.Write(trailer, 0, trailer.Length);

            Dlina += trailer.Length;


            rs.Close();
            //    wr.ContentLength = Dlina;

            // Конец передачи файлов

            WebResponse wresp = null;
            try
            {
                wresp = wr.GetResponse();
                Stream stream2 = wresp.GetResponseStream();
                StreamReader reader2 = new StreamReader(stream2);


            }
            catch (Exception ex)
            {
                Console.Out.Write(Environment.NewLine + "Error uploading file: " + ex);
                //    wresp.Close();
                wresp = null;
            }
            finally
            {
                wr = null;
            }
        }

        /*

        void req()
        { 
               var client = new RestClient("session.address");

        var request = new RestRequest("destination", Method.POST);
        request.AddParameter("application/json; charset=utf-8", content, ParameterType.RequestBody);
            request.RequestFormat = DataFormat.Json;
            request.Timeout = 600 * 1000;
           
            IRestResponse response = client.Execute(request);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                if (response.Content == null)
                    return new TaskResponse(
                        $"Ошибка {response.StatusCode} при обращении к серверу",
                        "HTTP_ERROR", "SYSTEM");
    }

    var responseString = response.Content;

    var resp = JObject.Parse(responseString);

          


}

*/
}

}
#endif