rule Win_Trojan_Vundo_498
{
strings:
	$a0 = { c1d04e25370200006a }


condition:
	$a0
}