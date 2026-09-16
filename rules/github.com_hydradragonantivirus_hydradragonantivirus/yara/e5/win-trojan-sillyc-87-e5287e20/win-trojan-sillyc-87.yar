rule Win_Trojan_SillyC_87
{
strings:
	$a0 = { d2cd2172eda3c301b440b9c500ba00f0cd2172deb8004233c933d2cd2172d3b440ba0001b9c5 }


condition:
	$a0
}