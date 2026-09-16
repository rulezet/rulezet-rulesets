rule Win_Trojan_Banload_2080
{
strings:
	$a0 = { 558becb81f214273bb49e1ca4d50e800000000582d }


condition:
	$a0
}