rule Win_Trojan_R_75
{
strings:
	$a0 = { e800008bf48b2c81ed07018db61601c604c3c604c68db62e01e80200eb0cb9a5018134 }


condition:
	$a0
}