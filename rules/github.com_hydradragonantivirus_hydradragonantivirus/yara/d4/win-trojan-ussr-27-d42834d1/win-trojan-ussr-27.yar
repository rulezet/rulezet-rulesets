rule Win_Trojan_USSR_27
{
strings:
	$a0 = { 83c30f33c08ec033f68cc0403dff0f76 }


condition:
	$a0
}