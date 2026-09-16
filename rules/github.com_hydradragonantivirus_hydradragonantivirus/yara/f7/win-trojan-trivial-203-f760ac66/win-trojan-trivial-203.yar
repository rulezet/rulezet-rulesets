rule Win_Trojan_Trivial_203
{
strings:
	$a0 = { 2193b126ba0001b440cd21b44febe6c32a2e636f6d00 }


condition:
	$a0
}