rule Win_Trojan_Bredolab_19
{
strings:
	$a0 = { 8bfb8bfb8bd933f88bf733c88bda0f88cb01000051598d000f89c1010000ffe8ffff7425ffff33f24f0bd303deff710803d7 }


condition:
	$a0
}