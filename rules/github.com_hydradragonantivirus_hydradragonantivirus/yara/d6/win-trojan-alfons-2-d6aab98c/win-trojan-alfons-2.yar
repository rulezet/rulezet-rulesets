rule Win_Trojan_Alfons_2
{
strings:
	$a0 = { e21fcc40c3fc1e06b452cd2133ed268b57fe8eda80 }


condition:
	$a0
}