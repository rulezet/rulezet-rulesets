rule Win_Trojan_Worm_23
{
strings:
	$a0 = { c9ba9803be9a03c60400cd2193b440b9cb02ba0001cd21e88201250f0091ba0001b440cd21 }


condition:
	$a0
}