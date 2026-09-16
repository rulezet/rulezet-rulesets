rule Win_Trojan_Dotter_1
{
strings:
	$a0 = { 505351b9580f2ea01c00bb1e00432e3007e2fa595b58eb02 }


condition:
	$a0
}