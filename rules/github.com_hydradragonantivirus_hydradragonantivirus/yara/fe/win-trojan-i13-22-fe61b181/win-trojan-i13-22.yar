rule Win_Trojan_I13_22
{
strings:
	$a0 = { 37ac2d6b6d0dc485dc60fbbf95d510d4e39a36792e6b93483abfe7cd2751c5d4a361c769bf5a7684 }


condition:
	$a0
}