rule _way__32_lil_AND_
{
strings:
	$a0 = { 0b0b0000[0-20]b1b10000[0-20]11100100 }

condition:
	$a0
}