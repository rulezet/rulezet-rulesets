rule Win_Trojan_Brackets_1
{
strings:
	$a0 = { cd2181ffcc447503e9a7001e5d4d8ec58bf32680 }


condition:
	$a0
}