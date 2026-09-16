rule Win_Trojan_Companion_31
{
strings:
	$a0 = { 4bbb0501268c4f04cd21c38bd7b82e5bae75fd66c705636f6d00cd2193b44f72b9b440b166eb }


condition:
	$a0
}