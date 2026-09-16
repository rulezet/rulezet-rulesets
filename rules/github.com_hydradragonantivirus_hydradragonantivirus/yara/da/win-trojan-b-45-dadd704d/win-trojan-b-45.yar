rule Win_Trojan_B_45
{
strings:
	$a0 = { 81c7eb0080ff7c9c750a26c6450cc360e8e77961b80103be1d02e817ff41cdc69d749e61 }


condition:
	$a0
}