rule LZSS__N_4096__F_18__T_2___32_big_AND_
{
strings:
	$a0 = { 00000fee[0-20]000000f0[0-20]00000fff[0-20]00000fff }

condition:
	$a0
}