rule Win_Trojan_NTZ_1
{
strings:
	$a0 = { cd21888e2d01b9d1008db65e018dbe1902a48a86190232862d01888619028d7cff8db61902a4 }


condition:
	$a0
}