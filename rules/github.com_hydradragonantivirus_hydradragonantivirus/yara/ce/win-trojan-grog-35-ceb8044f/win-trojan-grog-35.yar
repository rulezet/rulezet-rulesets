rule Win_Trojan_Grog_35
{
strings:
	$a0 = { cd218bd8b90300bafd00b43fcd21803efd00e97401 }


condition:
	$a0
}