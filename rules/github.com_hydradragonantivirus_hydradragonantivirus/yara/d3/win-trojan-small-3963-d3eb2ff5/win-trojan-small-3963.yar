rule Win_Trojan_Small_3963
{
strings:
	$a0 = { bfcbccb7f881c73565890789fe8d9fd01afe0481eb5416fe0453ff15f83641000500e023bf290731c08d7f0183c7024739df7ee5 }


condition:
	$a0
}