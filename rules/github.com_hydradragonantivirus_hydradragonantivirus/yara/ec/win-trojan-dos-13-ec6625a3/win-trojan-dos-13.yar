rule Win_Trojan_Dos_13
{
strings:
	$a0 = { b88485cd213ac475290e0e1f07bf00015783c618a5a5a4c3 }


condition:
	$a0
}