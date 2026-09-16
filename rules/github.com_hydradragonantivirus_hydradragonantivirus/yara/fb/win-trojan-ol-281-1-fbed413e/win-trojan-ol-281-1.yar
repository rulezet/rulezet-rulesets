rule Win_Trojan_Ol_281_1
{
strings:
	$a0 = { b919018a261003cd21721d81f9190175172ac0e81d }


condition:
	$a0
}