rule Win_Trojan_Tina_1
{
strings:
	$a0 = { c6c116b91b03bf3904fdac8a25aa30cc32e732c4884401e2f14656c3 }


condition:
	$a0
}