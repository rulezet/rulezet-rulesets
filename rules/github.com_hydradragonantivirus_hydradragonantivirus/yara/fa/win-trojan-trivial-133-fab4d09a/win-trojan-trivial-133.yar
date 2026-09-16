rule Win_Trojan_Trivial_133
{
strings:
	$a0 = { 2a00b44e8bd6cd2192b29eb8023dcd2193b4408bd6cd21b44febeb }


condition:
	$a0
}