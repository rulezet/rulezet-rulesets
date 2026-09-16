rule Win_Trojan_Trivial_130
{
strings:
	$a0 = { 1801cd21b8023dba9e00cd2193b44083c262cd21c3 }


condition:
	$a0
}