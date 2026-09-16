rule Win_Trojan_Victor_3
{
strings:
	$a0 = { ffffbbf00fcd21890e860081f9c1fe75 }


condition:
	$a0
}