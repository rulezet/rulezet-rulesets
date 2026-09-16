rule Win_Trojan_VGEN_683
{
strings:
	$a0 = { 2a005589e581ec0001bfca031e57bf02001e5731c0509a2d082a009ab0072a009a0e022a00b00050bf04021e57 }


condition:
	$a0
}