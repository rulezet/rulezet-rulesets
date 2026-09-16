rule Win_Trojan_DenZuk_3
{
strings:
	$a0 = { e4cd13720d33d2b92128bb007eb8 }


condition:
	$a0
}