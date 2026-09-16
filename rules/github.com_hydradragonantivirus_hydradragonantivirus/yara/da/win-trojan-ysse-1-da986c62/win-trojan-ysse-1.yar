rule Win_Trojan_Ysse_1
{
strings:
	$a0 = { 51b9023d8bc159cd219351b1408ae159b903008d954c03cd2151b902428bc159998bcacd2151 }


condition:
	$a0
}