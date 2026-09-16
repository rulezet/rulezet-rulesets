rule Win_Trojan_Crypted_30
{
strings:
	$a0 = { 9060909090 }


condition:
	$a0
}