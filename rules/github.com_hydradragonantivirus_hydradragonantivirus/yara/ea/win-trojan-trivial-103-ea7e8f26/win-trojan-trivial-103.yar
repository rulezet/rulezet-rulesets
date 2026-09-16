rule Win_Trojan_Trivial_103
{
strings:
	$a0 = { 2e2a00b44e8bd6cd21b8023dba9e00cd2193b4408bd6cd21c3 }


condition:
	$a0
}