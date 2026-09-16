rule Win_Trojan_Morid_4
{
strings:
	$a0 = { bf00??????57c3 }

	$a1 = { 83c74866813f58587501c3 }


condition:
	$a0 and $a1
}