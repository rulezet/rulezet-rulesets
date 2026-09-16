rule Win_Trojan_VGEN_734
{
strings:
	$a0 = { 03bd00000e170e1f06b8fe4bcd2180fc087503e901019ccd019c585b3bc372f4b840cacd2f3d3fca75728d963900 }


condition:
	$a0
}