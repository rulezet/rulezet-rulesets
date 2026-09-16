rule Win_Trojan_Crypted_32
{
strings:
	$a0 = { 90906090909090 }


condition:
	$a0
}