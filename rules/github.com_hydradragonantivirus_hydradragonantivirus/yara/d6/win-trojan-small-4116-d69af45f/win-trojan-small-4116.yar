rule Win_Trojan_Small_4116
{
strings:
	$a0 = { bd0b????558d9df52fa5aa8dbd7137a5 }


condition:
	$a0
}