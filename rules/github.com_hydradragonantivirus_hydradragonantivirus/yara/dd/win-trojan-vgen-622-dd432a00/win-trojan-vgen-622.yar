rule Win_Trojan_VGEN_622
{
strings:
	$a0 = { bc019a0d005a015589e5b800029acd02bc0181ec00028dbe00ff1657b80100509a7c09bc01bfe2001e57b8ff00 }


condition:
	$a0
}