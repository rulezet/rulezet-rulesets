rule Win_Trojan_Carfield_1
{
strings:
	$a0 = { d5bf0001bedf0503f72e8b8d1100cd }


condition:
	$a0
}