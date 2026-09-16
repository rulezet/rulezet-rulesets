rule Win_Trojan_Banload_2078
{
strings:
	$a0 = { 558bec83c4e0535633c08945e08945e48945e889 }

	$a1 = { 6f70656e }

	$a2 = { cbccc8c9d7cfc8cdcedbd8cad9da }


condition:
	$a0 and $a1 and $a2
}