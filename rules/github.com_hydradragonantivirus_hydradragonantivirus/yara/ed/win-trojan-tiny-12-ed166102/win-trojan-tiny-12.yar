rule Win_Trojan_Tiny_12
{
strings:
	$a0 = { 2abf9e0091b44ee80000565acd218bd7b82e5bae75fd66c705636f6d20cd2193b440b128c3 }


condition:
	$a0
}