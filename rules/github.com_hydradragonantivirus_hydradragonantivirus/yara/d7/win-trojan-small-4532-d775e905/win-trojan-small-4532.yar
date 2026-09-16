rule Win_Trojan_Small_4532
{
strings:
	$a0 = { ba21dae50f81ea2164a50f5252e83d000000e8 }


condition:
	$a0
}