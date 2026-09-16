rule RNG__original_numbers___32_lil_AND_
{
strings:
	$a0 = { ffffff7f[0-20]c8ad0000 }

condition:
	$a0
}