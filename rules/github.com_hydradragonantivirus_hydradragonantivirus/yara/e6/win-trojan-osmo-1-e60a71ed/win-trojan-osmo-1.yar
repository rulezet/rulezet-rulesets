rule Win_Trojan_Osmo_1
{
strings:
	$a0 = { 0e1fbe2f008b1e2c0090b9a80190301c46d1cb02dfe2f7 }


condition:
	$a0
}