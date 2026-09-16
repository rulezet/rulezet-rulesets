rule Win_Trojan_MSU_1
{
strings:
	$a0 = { fd005acd2172cdb440b912005a2bd1cd217213b8004233c98bd1cd21b440b9fd00ba0001cd }


condition:
	$a0
}