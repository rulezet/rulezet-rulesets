rule Win_Trojan_Crypt_159
{
strings:
	$a0 = { 2455e8(01|02|03|04)000000 }


condition:
	$a0
}