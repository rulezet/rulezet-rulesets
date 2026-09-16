rule Win_Trojan_Lapis_1
{
strings:
	$a0 = { 01cd21c3b80242cd21b440e8efffb800425a59cd211e0e1fb440ba0002e8deff1f1e07b449cd }


condition:
	$a0
}