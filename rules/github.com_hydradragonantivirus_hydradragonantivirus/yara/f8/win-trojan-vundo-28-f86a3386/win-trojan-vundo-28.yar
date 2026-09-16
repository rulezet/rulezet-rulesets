rule Win_Trojan_Vundo_28
{
strings:
	$a0 = { 807c24080156eb }

	$a1 = { 5e83c6??668136????56c3000000000000000000000000000000000000 }


condition:
	$a0 and $a1
}