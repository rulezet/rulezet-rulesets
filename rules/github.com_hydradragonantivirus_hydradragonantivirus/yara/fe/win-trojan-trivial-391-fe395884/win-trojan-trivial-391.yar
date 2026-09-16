rule Win_Trojan_Trivial_391
{
strings:
	$a0 = { bab1922bc980ec4b4681ea7591fccd21f9b824bf4eba4e37f881f2d037352682fccd21ba3f9481f23f }


condition:
	$a0
}