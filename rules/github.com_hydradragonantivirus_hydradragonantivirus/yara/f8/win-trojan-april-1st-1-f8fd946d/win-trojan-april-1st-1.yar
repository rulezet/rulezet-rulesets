rule Win_Trojan_April_1st_1
{
strings:
	$a0 = { bf0001bee804b900ff81e9e804b4ddcd21eb4090d31467ea79ea6ad50001680b0000d8047614d0030000800012 }


condition:
	$a0
}