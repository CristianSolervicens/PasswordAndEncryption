# Password & Encryption

Ac� reuno una serie de clases que simplifican el uso de, a mi
parecer, los mejores y m�s apropiados algoritmos de encriptaci�n
para los distintos usos.

### **Autor:** Cristian Solervic�ns

```
En Program.cs

Son llamados todas las clases implementadas

Password:
Encriptaci�n NO reversible para contrase�as, ac� la idea es
guardar un hash complejo de la contrase�a y para poder validar el
login, se repite el mismo proceso con la clave ingresada, si
coinciden, la contrase�a es correcta.

RSA:
Encriptaci�n con llave p�blica y desencriptaci�n con llave privada,
su desventaja el la longitud de la cadena encriptada.

TripleDES:
Esta encriptaci�n es lo suficientemente compleja como para confiar
en ella, est� aprobada para tarjetas de cr�dito e informaci�n
bancaria. El mensaje encriptado no es muy largo.

AesGCM:
Esta encriptaci�n tiene cuatro elementos activos en la encriptaci�n
y uno de ellos es din�mico "tag" (�nico para cada mensaje encriptado).

```


Espero que esta compilaci�n de algoritmos pueda serles de utilidad.


_Cristian Solervic�ns_