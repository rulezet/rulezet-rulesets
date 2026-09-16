rule Win_Trojan_VGEN_440
{
strings:
	$a0 = { 43cd212e890e2d012ec6062f0100b82435cd2153062e891e1d012e8c061f01b824251e52ba }


condition:
	$a0
}