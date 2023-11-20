// See https://aka.ms/new-console-template for more information

using PasswordAndEncryption;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;


int IterRounds = 2102501;
string myComplexPassword = "pzkkakYfaXKajMrxb";
string myComplexPassword2 = "pzkkakYfaXKajMrxb";

Password pass = new Password(IterRounds);
Password pass2 = new Password(IterRounds);

// Debe guardarse el Hash de la Clave y el Salt para poder realizar la posterior comparación
string HashedPass1 = pass.PasswordHash(myComplexPassword);
var Salt = pass.GetStringSalt();

Console.WriteLine($"El Salt generado es: {Salt}");

string HashedPass2 = pass2.PasswordHash(myComplexPassword2, Salt);



Console.WriteLine("");
if (HashedPass1 != HashedPass2)
{
    Console.WriteLine($"Horror, los Hash NO coinciden !!!! {HashedPass1} != {HashedPass2}");
}
else
{
    Console.WriteLine("Excelente, los Hash son Idénticos !!!!");
    Console.WriteLine($"{HashedPass1} == {HashedPass2}");
}

Console.WriteLine("");
Console.ReadLine();

Console.Clear();


// -------------------
// ENCRIPTACION RSA
// -------------------

Console.WriteLine("Encriptación RSA");
Console.WriteLine("");
NewRSA rsa = new NewRSA();  //Acá generamos las Llaves Pública y Privada

string pkPasswd = "iwf57yn783425y";

byte[] encryptedPrivateKey = rsa.ExportPrivateKey(100000, pkPasswd);
byte[] publicKey = rsa.ExportPublicKey();

// Las llaves deben ser guardadas de forma segura, por ejemplo en KeyVault
string b64_PrivateKey = Convert.ToBase64String(encryptedPrivateKey);
string b64_PublicKey = Convert.ToBase64String(publicKey);

Console.WriteLine($"publicKey: {b64_PublicKey}\n");
Console.WriteLine($"privateKey: { b64_PrivateKey}\n");

//Nuevamente a byte[]
encryptedPrivateKey = Convert.FromBase64String(b64_PrivateKey);
publicKey = Convert.FromBase64String(b64_PublicKey);

NewRSA rsa2 = new NewRSA(publicKey, encryptedPrivateKey, pkPasswd);

string messageToEncrypt = "Este es un mensaje super secreto o una clave importante que debo guardar con recelo";
Console.WriteLine(messageToEncrypt);

var encryptedStringMessage = rsa2.Encrypt(messageToEncrypt);
Console.WriteLine($"Encriptado: {encryptedStringMessage}\n");

var decryptedMessage = rsa2.Decrypt(encryptedStringMessage);
Console.WriteLine($"Desencriptado: {decryptedMessage}");

Console.WriteLine("");
NewRSA rsa3 = new NewRSA(publicKey);
string secondMessage = "Este es un segundo mensaje importante";
Console.WriteLine(secondMessage);
var encriptado = rsa3.Encrypt(secondMessage);
Console.WriteLine($"Para encriptar me basta la llave Pública: {encriptado}");
Console.WriteLine("");
Console.WriteLine("Para desecriptar Necesito la Privada...");

rsa3.ImportEncryptedPrivateKey(encryptedPrivateKey, pkPasswd);
var decripted = rsa3.Decrypt(encriptado);
Console.WriteLine($"Desencriptado: {decripted}");

Console.WriteLine("");
Console.ReadLine();

// TripleDES  Aceptada para Tarjetas de Crédito.

Console.Clear();
Console.WriteLine("TripleDES");
Console.WriteLine("");

var key = RandomNumberGenerator.GetBytes(16);
var iv = RandomNumberGenerator.GetBytes(8);

messageToEncrypt = "Este es un mensaje super secreto o una clave importante que debo guardar con recelo";
Console.WriteLine($"Mensaje: {messageToEncrypt}");
encriptado = TripleDESEncrypt.Encrypt(messageToEncrypt, key, iv);
Console.WriteLine($"Encriptado {encriptado}");
string desencriptado = TripleDESEncrypt.Decrypt(encriptado, key, iv);
Console.WriteLine($"Desencriptado {desencriptado}");
Console.WriteLine("");
Console.ReadLine();


// AesGCM (128) Aceptada para Tarjetas de Crédito.

Console.Clear();
Console.WriteLine("AesGCM 128");
Console.WriteLine("");

var gcmKey = RandomNumberGenerator.GetBytes(32);
var nonce = RandomNumberGenerator.GetBytes(12);
string metadata_validacion = "no es sólo metadata, es parte del proceso";
string tag;

messageToEncrypt = "Este es un mensaje super secreto o una clave importante que debo guardar con recelo";
Console.WriteLine($"Mensaje: {messageToEncrypt}");

(string encriptado, string tag) result = AesGcmEncryption.Encrypt(messageToEncrypt, gcmKey, nonce, metadata_validacion);
Console.WriteLine($"Encriptado = {result.encriptado}\n Tag: {result.tag}");

//La desencriptación debe estar siempre en un try, por si los elementos no calzan.
desencriptado = AesGcmEncryption.Decrypt(result.encriptado, gcmKey, nonce, result.tag, metadata_validacion);
Console.WriteLine($"Des-Encriptado = {desencriptado}");
Console.WriteLine("");
Console.ReadLine();
