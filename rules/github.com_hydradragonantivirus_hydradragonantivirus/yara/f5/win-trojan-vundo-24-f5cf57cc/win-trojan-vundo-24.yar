rule Win_Trojan_Vundo_24
{
strings:
	$a0 = { 807c24080156eb }

	$a1 = { 50494e }

	$a2 = { 56c300000000000000000000000000 }


condition:
	$a0 and $a1 and $a2
}