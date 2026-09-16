rule Win_Trojan_Peed_23
{
strings:
	$a0 = { 30c9e81e0000005589e5b8????????33450801d089c1c9c2080089eb81c3 }


condition:
	$a0
}