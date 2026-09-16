rule Win_Trojan_Alia_1
{
strings:
	$a0 = { 9dbb2900b90404b280dbe387db2e30179c9d43fafbfbfafafae2ee6b851080808080 }


condition:
	$a0
}