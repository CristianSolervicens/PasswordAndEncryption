# Password & Encryption

Acá reuno una serie de clases que simplifican el uso de, a mi
parecer, los mejores y más apropiados algoritmos de encriptación
para los distintos usos.

### **Autor:** Cristian Solervicéns

```
En Program.cs

Son llamados todas las clases implementadas

Password:
Encriptación NO reversible para contraseñas, acá la idea es
guardar un hash complejo de la contraseña y para poder validar el
login, se repite el mismo proceso con la clave ingresada, si
coinciden, la contraseña es correcta.

RSA:
Encriptación con llave pública y desencriptación con llave privada,
su desventaja el la longitud de la cadena encriptada.

TripleDES:
Esta encriptación es lo suficientemente compleja como para confiar
en ella, está aprobada para tarjetas de crédito e información
bancaria. El mensaje encriptado no es muy largo.

AesGCM:
Esta encriptación tiene cuatro elementos activos en la encriptación
y uno de ellos es dinámico "tag" (único para cada mensaje encriptado).

```


Espero que esta compilación de algoritmos pueda serles de utilidad.


_Cristian Solervicéns_