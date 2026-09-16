rule Win_Trojan_Waca_1
{
strings:
	$a0 = { 8204b4bdcd21fa80fcff7503e9a600bf0001b9a406 }


condition:
	$a0
}