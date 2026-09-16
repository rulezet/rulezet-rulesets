rule Win_Trojan_Trojan_160
{
strings:
	$a0 = { e0f98bd783c203061f0e07bb3000b8004b2eff1e1c }


condition:
	$a0
}