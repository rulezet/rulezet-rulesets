rule Win_Trojan_Trivial_436
{
strings:
	$a0 = { b99701ba0001cd21b43ecd21c30d0a54686520666c69 }


condition:
	$a0
}