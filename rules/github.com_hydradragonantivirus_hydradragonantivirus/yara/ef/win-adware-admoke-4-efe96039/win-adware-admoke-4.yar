rule Win_Adware_Admoke_4
{
strings:
	$a0 = { 6561642e636f6d2f7365742f4e6577496e666f332e74 }

	$a1 = { 6b6561642e636f6d2f4e657753657475 }


condition:
	$a0 and $a1
}