rule Win_Trojan_Small_4427
{
strings:
	$a0 = { e8040000004f2e4200588b00505068ec }


condition:
	$a0
}