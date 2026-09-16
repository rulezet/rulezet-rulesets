rule Win_Trojan_Squeaker_1
{
strings:
	$a0 = { ff2e28002e8c1e3a00b47fcd2180fc807503e92cff }


condition:
	$a0
}