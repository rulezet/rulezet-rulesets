rule Win_Trojan_Phalcon_4
{
strings:
	$a0 = { 0483c62d908bfeac32c4aae2fac3 }


condition:
	$a0
}