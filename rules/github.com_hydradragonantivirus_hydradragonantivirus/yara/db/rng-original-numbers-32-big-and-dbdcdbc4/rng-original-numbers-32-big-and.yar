rule RNG__original_numbers___32_big_AND_
{
strings:
	$a0 = { 7fffffff[0-20]0000adc8 }

condition:
	$a0
}