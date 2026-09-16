rule Win_Trojan_VGEN_429
{
strings:
	$a0 = { 058bdc83c30fb104d3ebb44acd21bf6d02be4e02b90c00f3a4ba44028b0e6802b44ecd217279bf4e02be9e00b90c }


condition:
	$a0
}