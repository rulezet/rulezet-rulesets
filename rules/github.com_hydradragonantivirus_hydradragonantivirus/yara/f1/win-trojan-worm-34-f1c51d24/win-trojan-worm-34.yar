rule Win_Trojan_Worm_34
{
strings:
	$a0 = { 03f8b05caab87e6d7478aba0????4000aab82e657865ab32c0aafe05????400061c3??60b900200000b855524c3d8b35????400046390674 }


condition:
	$a0
}