rule Win_Trojan_Trivial_96
{
strings:
	$a0 = { b44efec6cd21b8013dba9e00cd2193b440cd }


condition:
	$a0
}