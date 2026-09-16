rule Win_Spyware_ye_139
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]88569267a3c2f5a7c9f69903a3c0f0 }


condition:
	$a0
}