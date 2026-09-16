rule Win_Trojan_Kitana_10
{
strings:
	$a0 = { 03cd13381f740cc747fe55aab80203b701cd13c30e1fff0e1304cd12c1e0068ec033ffb1 }


condition:
	$a0
}