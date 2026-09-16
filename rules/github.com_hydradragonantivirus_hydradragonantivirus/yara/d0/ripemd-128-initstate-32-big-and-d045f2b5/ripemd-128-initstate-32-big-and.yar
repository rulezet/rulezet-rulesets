rule RIPEMD_128_InitState__32_big_AND_
{
strings:
	$a0 = { 10325476[0-20]67452301[0-20]efcdab89[0-20]98badcfe }

condition:
	$a0
}