rule Win_Trojan_Vgen_24
{
strings:
	$a0 = { 52061e5756e800005bbea55abfaa550e0781c3e80381fbe8037303e99f0053b80102ba8000b90100cd135b7303 }


condition:
	$a0
}