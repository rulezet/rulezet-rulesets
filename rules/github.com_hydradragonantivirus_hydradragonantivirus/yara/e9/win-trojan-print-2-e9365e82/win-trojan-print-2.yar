rule Win_Trojan_Print_2
{
strings:
	$a0 = { 33c08ed0bc00f01e161fa113042d02 }


condition:
	$a0
}