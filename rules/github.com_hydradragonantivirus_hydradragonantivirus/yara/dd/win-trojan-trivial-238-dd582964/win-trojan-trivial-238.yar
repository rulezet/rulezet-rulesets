rule Win_Trojan_Trivial_238
{
strings:
	$a0 = { b43ecd21b44febe2cd202a2e632a00 }


condition:
	$a0
}