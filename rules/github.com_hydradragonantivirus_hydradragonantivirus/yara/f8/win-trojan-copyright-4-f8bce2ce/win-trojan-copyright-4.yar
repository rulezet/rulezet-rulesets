rule Win_Trojan_Copyright_4
{
strings:
	$a0 = { 4a75f2e2ea33c0cd16b80006b70733c9b618b24fcd10e9 }


condition:
	$a0
}