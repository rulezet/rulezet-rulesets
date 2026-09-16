rule Win_Trojan_OopsTmp_1
{
strings:
	$a0 = { 022e803e3d050075473d44307538b85530cf2ec6063d0501cd212ec6063d05000653522e8b1ed5018cc24a3bd375 }


condition:
	$a0
}