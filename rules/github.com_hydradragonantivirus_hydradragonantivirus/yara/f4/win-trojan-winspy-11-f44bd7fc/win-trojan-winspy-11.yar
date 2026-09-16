rule Win_Trojan_Winspy_11
{
strings:
	$a0 = { 8c3c4000ac3c4000bc3c4000c83c4000e03c4000fc3c40001c3d4000 }


condition:
	$a0
}