rule Win_Trojan_Stonsky_1
{
strings:
	$a0 = { 4bcd213c787548e9c900b462cd218edb8ec3a1020080 }


condition:
	$a0
}