rule Win_Trojan_Alabama_5
{
strings:
	$a0 = { e800005e81ee2901b968058ec5bbffff }


condition:
	$a0
}