rule Win_Trojan_N_3
{
strings:
	$a0 = { 8b96b9028db61100b9520131144646e2fac3 }


condition:
	$a0
}