rule Win_Trojan_Sov_2
{
strings:
	$a0 = { 33c0aaba8302b8023dcd217303eb71 }


condition:
	$a0
}