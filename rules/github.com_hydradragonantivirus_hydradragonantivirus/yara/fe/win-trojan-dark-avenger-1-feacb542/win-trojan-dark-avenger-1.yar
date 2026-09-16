rule Win_Trojan_Dark_Avenger_1
{
strings:
	$a0 = { d590cd213d032a90745c8bc49040 }


condition:
	$a0
}