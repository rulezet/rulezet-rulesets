rule Win_Trojan_Otto_2
{
strings:
	$a0 = { e800005e5681ee0801582d0001a2ff0056b97b0181c62901 }


condition:
	$a0
}