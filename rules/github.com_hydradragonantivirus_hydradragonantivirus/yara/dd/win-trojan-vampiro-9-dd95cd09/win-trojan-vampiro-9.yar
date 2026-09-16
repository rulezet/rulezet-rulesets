rule Win_Trojan_Vampiro_9
{
strings:
	$a0 = { 1e8becb400cd1a8b6efa81ed0801badd058bca2e8a961e01bf2901eb01002e3013b419cd2147e2f6 }


condition:
	$a0
}