rule Win_Trojan_Sojax_1
{
strings:
	$a0 = { 53637269707446696c65446972 }

	$a1 = { 45786546696c65446972 }

	$a2 = { 536576657255726c }

	$a3 = { 416464696e666f }

	$a4 = { 2f636f756e742f636f756e742e706870 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}