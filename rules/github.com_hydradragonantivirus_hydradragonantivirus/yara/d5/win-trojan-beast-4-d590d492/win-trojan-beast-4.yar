rule Win_Trojan_Beast_4
{
strings:
	$a0 = { cd21b824255a1fcd21061fbf000157c2ffffb44fcd21 }


condition:
	$a0
}