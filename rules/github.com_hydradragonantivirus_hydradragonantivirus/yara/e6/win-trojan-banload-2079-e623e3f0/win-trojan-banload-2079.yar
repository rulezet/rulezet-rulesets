rule Win_Trojan_Banload_2079
{
strings:
	$a0 = { 558bec83c4f0b8285e4700e8d402f9ffa1a48a47 }

	$a1 = { a76b65736861 }


condition:
	$a0 and $a1
}