rule Win_Trojan_Mururoa_3
{
strings:
	$a0 = { 2990e207eb1f905eeb1d903014eb1390b92200eb07908a945d09ebf481c65e09ebe946ebddebb6 }


condition:
	$a0
}