rule Win_Trojan_L_22
{
strings:
	$a0 = { ba1f01cd21e8e5ffc3e8d3ff721b515333c933d2b4428b1e1c01cd215a598b1e1c01b440cd21 }


condition:
	$a0
}