rule Win_Trojan_N_8
{
strings:
	$a0 = { 46e2fac33e8b963a028db61200b91001ebeb }


condition:
	$a0
}