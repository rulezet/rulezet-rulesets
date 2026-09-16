rule Win_Trojan_DenZuk_1
{
strings:
	$a0 = { 2128bb007eb80902cd13b83c7c50c3 }


condition:
	$a0
}