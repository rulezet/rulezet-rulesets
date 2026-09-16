rule Win_Trojan_Zbot_1297
{
strings:
	$a0 = { eb04212121[3]eb04212121[3]eb04212121[3]eb04212121[3]eb04212121[8]eb04212121 }


condition:
	$a0
}