rule Win_Trojan_B_37
{
strings:
	$a0 = { f503bf1704be0600e8890051b90300b440bafb03cd21b44059ba1704cd2132c0e83100baf803cd }


condition:
	$a0
}