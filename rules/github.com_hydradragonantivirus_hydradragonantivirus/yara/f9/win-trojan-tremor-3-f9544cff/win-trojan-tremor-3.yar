rule Win_Trojan_Tremor_3
{
strings:
	$a0 = { 8ce2be9c0285c2bdf2f636291c81c3e93a7a004646452e75f1 }


condition:
	$a0
}