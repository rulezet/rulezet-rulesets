rule Win_Trojan_L_23
{
strings:
	$a0 = { b8ff0850e8e10159b82b0950e8d90159b8620950e8d101 }


condition:
	$a0
}