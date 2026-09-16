rule Win_Trojan_SillyC_250
{
strings:
	$a0 = { e80200eb26b9f1008dbe3301c00d??47e0fac686160104c3 }


condition:
	$a0
}