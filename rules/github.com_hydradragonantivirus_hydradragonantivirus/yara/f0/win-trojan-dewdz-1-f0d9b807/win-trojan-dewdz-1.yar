rule Win_Trojan_DEWDZ_1
{
strings:
	$a0 = { 2ebeed02cd21b41aba00ffcd21c3 }


condition:
	$a0
}