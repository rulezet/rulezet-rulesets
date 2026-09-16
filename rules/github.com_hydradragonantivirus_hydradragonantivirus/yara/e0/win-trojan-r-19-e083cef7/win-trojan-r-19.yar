rule Win_Trojan_R_19
{
strings:
	$a0 = { 3e8b96a9048db61101b9cc0131144646e2fac3 }


condition:
	$a0
}