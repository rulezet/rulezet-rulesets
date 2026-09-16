rule Win_Trojan_Bredolab_15
{
strings:
	$a0 = { 6a??ff15082040006a??ff15082040006a??ff15082040006a??ff1508204000 }


condition:
	$a0
}