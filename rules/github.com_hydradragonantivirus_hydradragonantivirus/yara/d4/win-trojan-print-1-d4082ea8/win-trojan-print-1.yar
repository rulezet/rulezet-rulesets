rule Win_Trojan_Print_1
{
strings:
	$a0 = { b801038a365f01b90100cd6de824005a595f5e5b }


condition:
	$a0
}