rule Win_Trojan_MetallicaII_1
{
strings:
	$a0 = { 06505153521e8ac42c4b7413e9fe0283c418cfea }


condition:
	$a0
}