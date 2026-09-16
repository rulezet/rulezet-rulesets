rule Win_Trojan_Mummy_4
{
strings:
	$a0 = { a0d60251b9b0013004f6d8d0c046e2f759c3 }


condition:
	$a0
}