rule Win_Trojan_BerlinHQ_1
{
strings:
	$a0 = { a39f01bab203b9b201b440cd21c60612024eb8004233c933d2cd21b440ba0001b9b201cd21 }


condition:
	$a0
}