This challenge gave me a binary which contains the flag. 

Challenge info:

>We've got this program that's supposed to check a password, and we're not quite sure how it works. Could you take a look at it and see about finding the password it's looking for?

I initially ran ltrace to run the binary and see what it did, I could see what looked like most of a flag.


```sh
kali@kali-[~/boxes/ctfs/cybergames/strings]$ltrace ./strings 
printf("Input the password: ")                                                       = 20
fgets(Input the password: password
"password\n", 256, 0x7f68e2dab9a0)                                             = 0x7ffc50e2e590
strcmp("password\n", "MetaCTF{this_is_the_most_secure_"...)                          = 35
puts("Begone!!"Begone!!
)                                                                     = 9
+++ exited (status 0) +++
```

Considering the name of the challenge I decided to run strings on the binary.


```sh
kali@kali-[~/boxes/ctfs/cybergames/strings]$strings strings | grep MetaCTF
MetaCTF{this_is_the_most_secure_ever}
```