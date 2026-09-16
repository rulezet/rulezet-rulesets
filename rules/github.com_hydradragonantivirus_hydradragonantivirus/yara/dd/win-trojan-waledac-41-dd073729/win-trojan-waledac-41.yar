rule Win_Trojan_Waledac_41
{
strings:
	$a0 = { 66d3d6d2cf80c4d4e8cdfdfffffd162c88eed2b38d008f4424fcc1c10580f19ae808ffffff31 }


condition:
	$a0
}