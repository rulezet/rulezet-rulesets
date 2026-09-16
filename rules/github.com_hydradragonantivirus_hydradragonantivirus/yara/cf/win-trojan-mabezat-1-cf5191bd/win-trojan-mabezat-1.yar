rule Win_Trojan_Mabezat_1
{
strings:
	$a0 = { 5383ec44b823104000b9000000008a1880????881883c00183c10181f937d1000075eb }


condition:
	$a0
}