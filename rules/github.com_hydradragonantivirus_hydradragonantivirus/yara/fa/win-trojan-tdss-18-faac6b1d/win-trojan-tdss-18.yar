rule Win_Trojan_TDSS_18
{
strings:
	$a0 = { 64ff3530000000e9d1fdffff905383c4 }

	$a1 = { 062c7133ec344475656e84666c4d66 }


condition:
	$a0 and $a1
}