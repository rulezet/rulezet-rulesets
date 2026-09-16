rule Win_Trojan_Small_4426
{
strings:
	$a0 = { 6a00c70424a63042008d04240f6e100f7ed050ba717af30f52506aff6a00e8 }


condition:
	$a0
}