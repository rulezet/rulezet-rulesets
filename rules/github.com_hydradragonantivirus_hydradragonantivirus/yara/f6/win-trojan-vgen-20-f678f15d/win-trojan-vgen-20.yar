rule Win_Trojan_Vgen_20
{
strings:
	$a0 = { 018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe37e033801860153e800005b8bfe4f1eff57 }


condition:
	$a0
}