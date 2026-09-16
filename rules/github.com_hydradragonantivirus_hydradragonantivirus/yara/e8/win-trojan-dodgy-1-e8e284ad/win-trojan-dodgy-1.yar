rule Win_Trojan_Dodgy_1
{
strings:
	$a0 = { bf14041fc606a104ea4fff0d8b05c1e0062dc0075050b801020e07bb007eb90f00ba8000cd13c7 }


condition:
	$a0
}