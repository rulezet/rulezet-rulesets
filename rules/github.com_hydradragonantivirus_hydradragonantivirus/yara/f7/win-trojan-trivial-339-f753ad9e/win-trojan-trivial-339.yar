rule Win_Trojan_Trivial_339
{
strings:
	$a0 = { b90100ba3d01b44ecd217302eb1eb8023dba9e00cd217302eb128bd8e80f00b44fba8200cd217302eb02ebe2cd20ba0001b440b94300cd21b43ecd21c32a2e43 }


condition:
	$a0
}