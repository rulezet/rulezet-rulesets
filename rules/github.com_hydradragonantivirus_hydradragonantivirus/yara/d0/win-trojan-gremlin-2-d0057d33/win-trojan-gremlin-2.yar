rule Win_Trojan_Gremlin_2
{
strings:
	$a0 = { cd13eb003c027510b403b006b504b1 }


condition:
	$a0
}