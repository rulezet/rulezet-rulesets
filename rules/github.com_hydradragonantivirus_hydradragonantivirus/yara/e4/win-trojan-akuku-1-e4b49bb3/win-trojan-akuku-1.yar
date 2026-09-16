rule Win_Trojan_Akuku_1
{
strings:
	$a0 = { e800005e8bd681c62a01bf0001a5a481 }


condition:
	$a0
}