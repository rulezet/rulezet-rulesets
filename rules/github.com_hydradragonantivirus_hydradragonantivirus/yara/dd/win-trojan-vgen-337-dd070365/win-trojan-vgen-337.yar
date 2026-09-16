rule Win_Trojan_VGEN_337
{
strings:
	$a0 = { 1f018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe34c028a14460ad27406b402cd21ebf3c346 }


condition:
	$a0
}