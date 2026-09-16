rule Win_Trojan_Pregnant_1
{
strings:
	$a0 = { 9f04be1001b407302446e2fbeb7990 }


condition:
	$a0
}