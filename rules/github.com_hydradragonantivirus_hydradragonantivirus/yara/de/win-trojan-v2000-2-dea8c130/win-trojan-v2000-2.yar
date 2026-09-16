rule Win_Trojan_V2000_2
{
strings:
	$a0 = { cd2f5a1f2e8994a7072e8c9ca9072e }


condition:
	$a0
}