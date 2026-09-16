rule Win_Trojan_PS_4
{
strings:
	$a0 = { e90200????be1601b9bf012e8104????83c6024975f5 }


condition:
	$a0
}