rule Win_Trojan_Oolong_1
{
strings:
	$a0 = { ec8b7e00b903014fe2fd83c4020e1f8c853b062ec6061606000e07b4f9cd21c6851b06003d34127405c6851b0601b4 }


condition:
	$a0
}