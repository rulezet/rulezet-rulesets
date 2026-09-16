rule anti_debug__Detect_and_crash_SoftICE_with_an_illegal_form_of_the_instruction_CMPXCHG8B__8_byt_4_
{
strings:
	$a0 = { f00fc7c8 }

condition:
	$a0
}