rule Win_Trojan__0114_0006_000_1
{
strings:
	$a0 = { 51b90300b440ba1a04cd21b44059ba3604cd2132c0e83100ba1704cd215a5980e1e080c901b801 }


condition:
	$a0
}