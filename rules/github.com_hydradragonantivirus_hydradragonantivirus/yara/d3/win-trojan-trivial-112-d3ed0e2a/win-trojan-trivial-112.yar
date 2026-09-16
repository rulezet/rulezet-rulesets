rule Win_Trojan_Trivial_112
{
strings:
	$a0 = { 2a0051b44e87d1cd21b8023dba9e00cd2193b440495acd21 }


condition:
	$a0
}