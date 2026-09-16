rule Win_Trojan_Small_4446
{
strings:
	$a0 = { 8d05????400050506814??0f00e86b00000051ff35 }


condition:
	$a0
}