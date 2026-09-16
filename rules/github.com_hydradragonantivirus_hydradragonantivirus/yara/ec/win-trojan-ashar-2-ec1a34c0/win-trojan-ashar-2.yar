rule Win_Trojan_Ashar_2
{
strings:
	$a0 = { a0067ca2097c8b0e077c890e0a7ce859 }


condition:
	$a0
}