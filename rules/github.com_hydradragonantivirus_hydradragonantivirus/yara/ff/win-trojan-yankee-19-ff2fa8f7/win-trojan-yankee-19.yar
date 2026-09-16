rule Win_Trojan_Yankee_19
{
strings:
	$a0 = { ba0002520e5143cfb440eb0390b43fe8090072023bc1c3 }


condition:
	$a0
}