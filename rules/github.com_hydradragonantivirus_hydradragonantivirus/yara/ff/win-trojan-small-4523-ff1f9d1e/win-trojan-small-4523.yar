rule Win_Trojan_Small_4523
{
strings:
	$a0 = { bd??324200ba??d842008b1affd301d5 }


condition:
	$a0
}