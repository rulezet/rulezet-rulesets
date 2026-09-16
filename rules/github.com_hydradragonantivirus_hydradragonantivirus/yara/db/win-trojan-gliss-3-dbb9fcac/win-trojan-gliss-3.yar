rule Win_Trojan_Gliss_3
{
strings:
	$a0 = { df048984e1048984e3048984e5048bfe83c712b92601 }


condition:
	$a0
}