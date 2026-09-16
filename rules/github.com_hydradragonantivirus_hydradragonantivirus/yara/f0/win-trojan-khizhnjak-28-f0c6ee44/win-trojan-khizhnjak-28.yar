rule Win_Trojan_Khizhnjak_28
{
strings:
	$a0 = { 0201b90001bb00002e8a078887ce0243e2f6baae02b920 }


condition:
	$a0
}