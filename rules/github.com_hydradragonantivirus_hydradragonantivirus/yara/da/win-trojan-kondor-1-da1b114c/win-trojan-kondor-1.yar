rule Win_Trojan_Kondor_1
{
strings:
	$a0 = { 9a0000b1005589e5b800019a7c02b10081ec0001bf00000e57b8200050bf46011e579a88008f00ff365e01ff365c01bf }


condition:
	$a0
}