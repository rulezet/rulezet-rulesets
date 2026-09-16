rule Win_Trojan_K_11
{
strings:
	$a0 = { c7074673f9f51fc3f606280101740d8cc00510000106 }


condition:
	$a0
}