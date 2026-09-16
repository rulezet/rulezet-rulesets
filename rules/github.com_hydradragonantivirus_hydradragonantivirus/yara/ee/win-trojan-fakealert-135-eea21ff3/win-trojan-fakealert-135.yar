rule Win_Trojan_Fakealert_135
{
strings:
	$a0 = { e9a70100000000000dc87c00ad0000818300f9000b28c4008a0c0000000d20c8 }


condition:
	$a0
}