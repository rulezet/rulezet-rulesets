rule Win_Trojan_NewAids_1
{
strings:
	$a0 = { 5e83c60d90b90001515fb9030057f3a45f525ee81600 }


condition:
	$a0
}