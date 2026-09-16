rule Win_Trojan_Vundo_328
{
strings:
	$a0 = { e80?000000[0-10]5eb9??(00|01)0000[0-10]03f1[0-10]8b36[0-25]3bf177[0-10]cd20 }


condition:
	$a0
}