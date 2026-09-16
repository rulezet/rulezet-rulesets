rule Win_Trojan_IronMaiden_1
{
strings:
	$a0 = { cd215f0e1f8b855702a300018aa5 }


condition:
	$a0
}