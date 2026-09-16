rule Win_Trojan_Peed_391
{
strings:
	$a0 = { e90f00000039d80f8e01000000c358e97c000000babbb440 }


condition:
	$a0
}