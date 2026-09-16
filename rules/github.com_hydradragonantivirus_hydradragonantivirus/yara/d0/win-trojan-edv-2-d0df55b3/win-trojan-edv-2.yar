rule Win_Trojan_EDV_2
{
strings:
	$a0 = { 751c80fe0175175b071f5883 }


condition:
	$a0
}