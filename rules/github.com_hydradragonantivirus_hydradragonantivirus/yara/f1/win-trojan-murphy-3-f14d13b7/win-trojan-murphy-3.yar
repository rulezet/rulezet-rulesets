rule Win_Trojan_Murphy_3
{
strings:
	$a0 = { cb582e8b8475fc2ea300012e8b8477fc }


condition:
	$a0
}