rule Win_Trojan_DM_8
{
strings:
	$a0 = { bf020226381d74251e8db6ccfe8a664890e8d1ffb9c1 }


condition:
	$a0
}