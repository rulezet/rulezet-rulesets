rule Win_Trojan_OldYankee_2
{
strings:
	$a0 = { 81fb7a0073f4cd208cda03da891e0200 }


condition:
	$a0
}