rule Win_Trojan_Leech_1
{
strings:
	$a0 = { ff0730044681feff0772f7595ab440e85b00 }


condition:
	$a0
}