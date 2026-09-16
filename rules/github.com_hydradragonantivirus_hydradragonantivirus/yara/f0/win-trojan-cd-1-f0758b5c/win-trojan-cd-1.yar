rule Win_Trojan_CD_1
{
strings:
	$a0 = { e90300de5c3fe80300e9de045850c3 }


condition:
	$a0
}