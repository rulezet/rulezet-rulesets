rule Win_Trojan_Christmas_4
{
strings:
	$a0 = { 7503b077cf80fc4b7403e9bc01505351521e065756 }


condition:
	$a0
}