rule Win_Trojan_KID_1
{
strings:
	$a0 = { 0e56742b813f4d5a742587dab002e82200b802013d01017216b440e82d00b80040e80f00ba00 }


condition:
	$a0
}