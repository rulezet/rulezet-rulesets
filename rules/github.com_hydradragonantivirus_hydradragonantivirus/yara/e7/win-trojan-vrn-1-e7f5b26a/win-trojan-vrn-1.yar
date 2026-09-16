rule Win_Trojan_VRN_1
{
strings:
	$a0 = { 3500409090eb0490eb0490a4ebfa3bc372ecc3 }


condition:
	$a0
}