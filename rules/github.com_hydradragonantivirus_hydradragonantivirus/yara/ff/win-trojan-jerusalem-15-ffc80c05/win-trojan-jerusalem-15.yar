rule Win_Trojan_Jerusalem_15
{
strings:
	$a0 = { 3805e0f98bd783c203b8004b061f0e07bb }


condition:
	$a0
}