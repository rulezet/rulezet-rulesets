rule Win_Trojan_Philis_95
{
strings:
	$a0 = { 81f7fb68000081f7fb68000060510f00c159e80000000056575f5e56d3ce5e5a }


condition:
	$a0
}