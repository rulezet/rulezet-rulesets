rule Win_Trojan_Niceday_1
{
strings:
	$a0 = { cd2181f9c6077c7c7f0c80fe057c }


condition:
	$a0
}