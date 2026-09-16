rule Win_Trojan_Trivial_421
{
strings:
	$a0 = { b9df00ba0001cd21b43ecd21c30d0a54686520646973 }


condition:
	$a0
}