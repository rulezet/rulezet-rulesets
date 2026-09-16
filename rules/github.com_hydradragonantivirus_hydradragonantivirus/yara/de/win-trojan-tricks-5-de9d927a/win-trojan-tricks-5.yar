rule Win_Trojan_Tricks_5
{
strings:
	$a0 = { 01cd21582bc9f7f1eb119083c406bb0601b97e00908030aa43e2fa595bc3e900002a2e434f4d }


condition:
	$a0
}