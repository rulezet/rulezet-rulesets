rule Win_Trojan_Sarov_1
{
strings:
	$a0 = { e800005f81efd603bad303803556474a75f9e9d8fd }


condition:
	$a0
}