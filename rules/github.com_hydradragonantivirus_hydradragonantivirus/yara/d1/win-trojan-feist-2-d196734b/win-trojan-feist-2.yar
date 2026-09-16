rule Win_Trojan_Feist_2
{
strings:
	$a0 = { b440b99e02ba0001cd217302eb5b }


condition:
	$a0
}