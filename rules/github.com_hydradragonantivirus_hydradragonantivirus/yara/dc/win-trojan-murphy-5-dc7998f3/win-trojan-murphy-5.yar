rule Win_Trojan_Murphy_5
{
strings:
	$a0 = { 3dc8057304585af9c38bf88bea592bc1 }


condition:
	$a0
}