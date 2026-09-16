rule Win_Trojan_Kamikaze_2
{
strings:
	$a0 = { 06d21f65c606ce1f68c606d31f78c6 }


condition:
	$a0
}