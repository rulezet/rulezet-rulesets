rule Win_Trojan_Gen_220
{
strings:
	$a0 = { 8701e0caa1eef5ee39ca87ba7f0675079d729df80ab7f66f4fc6cb22adcd91c0f4e86002d9 }


condition:
	$a0
}