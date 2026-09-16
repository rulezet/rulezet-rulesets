rule Win_Trojan_Jocker_3
{
strings:
	$a0 = { 0d000e57bf4d1b1e57b80c00509a90 }


condition:
	$a0
}