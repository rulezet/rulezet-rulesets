rule Win_Trojan_Jerusalem_19
{
strings:
	$a0 = { e0f98bd783c203b8004b061f0e07bb2c0053515256 }


condition:
	$a0
}