rule Win_Trojan_Faust_1
{
strings:
	$a0 = { b87a005006b8fd005026c706fd00f3a4 }


condition:
	$a0
}