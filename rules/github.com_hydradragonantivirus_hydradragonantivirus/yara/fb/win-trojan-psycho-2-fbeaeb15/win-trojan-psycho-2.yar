rule Win_Trojan_Psycho_2
{
strings:
	$a0 = { b96e0483c6308bfee80700ac32c4aae2fac3c356e8e0ffb9ab045a83c2b2b440cd21e8d2ff }


condition:
	$a0
}