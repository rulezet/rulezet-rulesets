rule Win_Trojan_Bebe_3
{
strings:
	$a0 = { 4233c933d28b1e1c00cd21b4408d160000b90e00 }


condition:
	$a0
}