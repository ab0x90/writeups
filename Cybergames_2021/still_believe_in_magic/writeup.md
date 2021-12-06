# Still Believe In Magic

This challenge gave me a tar file and explains that there is a file inside with no extension, figure out what the file is.

Challenge info:
>We found an archive with a file in it, but there was no file extension so we're not sure what it is. Can you figure out what kind of file it is and then open it?

The original file.

```sh
kali@kali-[~/boxes/ctfs/cybergames/magic_file]$ls -al
total 12
drwxr-xr-x  2 kali kali 4096 Dec  6 12:41 .
drwxr-xr-x 23 kali kali 4096 Dec  5 10:39 ..
-rw-r--r--  1 kali kali  584 Dec  3 18:58 magic.tar.gz
```

Extract the file.

```sh
kali@kali-[~/boxes/ctfs/cybergames/magic_file]$tar -xvf magic.tar.gz 
magic
```

Running file on 'magic' reavels it is a zip archive. This is due to the magic bytes at the beginning of every file that can identify the file, even with no extension.

```sh
kali@kali-[~/boxes/ctfs/cybergames/magic_file]$file magic
magic: Zip archive data, at least v2.0 to extract
```

i renamed 'magic' to 'magic.zip' and unzipped it.

```sh
kali@kali-[~/boxes/ctfs/cybergames/magic_file]$unzip magic.zip 
Archive:  magic.zip
  inflating: magic.txt               
   creating: __MACOSX/
  inflating: __MACOSX/._magic.txt   
```

Magic.txt contained the flag for this challenge.

```sh
kali@kali-[~/boxes/ctfs/cybergames/magic_file]$cat magic.txt 
MetaCTF{was_it_a_magic_trick_or_magic_bytes?}
```
