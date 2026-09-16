rule Win_Trojan_VGEN_747
{
strings:
	$a0 = { 029090e800005a83ea03525d8bf281c61602bf0001b90500acaae2fcbe8200ac3c5b7503e91201b42acd2180fe0c75 }


condition:
	$a0
}