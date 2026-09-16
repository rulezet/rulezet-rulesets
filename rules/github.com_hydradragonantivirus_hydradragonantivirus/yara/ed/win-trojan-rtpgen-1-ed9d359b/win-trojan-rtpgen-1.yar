rule Win_Trojan_RTPGen_1
{
strings:
	$a0 = { bb030133d2e8d3045083ea0383c1038bfa1e07b0e9aa582d0301ab5bb440cd21b43ecd2107 }


condition:
	$a0
}