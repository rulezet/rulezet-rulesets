rule Win_Trojan_Virut_199
{
strings:
	$a0 = { e813000000??8af2b9??180000301002d640e2f9c30f31c3558b6c2404816c2404????0000e8ebffffff8bc8e8e4ffffff2bc13d0001000073468b5c240881e300f0ffff81ed051040008a????????????????5a74088d9b00f0ffffebec }


condition:
	$a0
}