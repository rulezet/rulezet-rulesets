rule Win_Trojan_VS_12
{
strings:
	$a0 = { d2001e57b80100509a6907c6009a9102c600bfd2001e57bfa6031e57b8411f50bfe8221e579a54 }


condition:
	$a0
}