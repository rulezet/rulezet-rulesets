rule Win_Trojan_Companion_30
{
strings:
	$a0 = { 4f04061e071fcd21c38bd7b82e5bae75fd66c705636f6d00cd2193b44f72bbb440b164ebb5 }


condition:
	$a0
}