rule Win_Trojan_Trivial_321
{
strings:
	$a0 = { 01b44ecd217302cd20ba9e00b8023dcd217302ebf2e80900b44fba8000cd2173e8ba0001b440b93a00cd21b43ecd21c3 }


condition:
	$a0
}