rule Win_Trojan_Trivial_420
{
strings:
	$a0 = { c9b44ecd210ac0752db002ba9e00b43dcd2193b95b00ba0001b440cd21 }


condition:
	$a0
}