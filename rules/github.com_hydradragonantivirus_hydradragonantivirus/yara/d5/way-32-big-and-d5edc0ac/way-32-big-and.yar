rule way__32_big_AND_
{
strings:
	$a0 = { 00000b0b[0-20]0000b1b1[0-20]aaaaaaaa[0-20]55555555[0-20]cccccccc[0-20]33333333[0-20]f0f0f0f0[0-20]0f0f0f0f[0-20]00011011 }

condition:
	$a0
}