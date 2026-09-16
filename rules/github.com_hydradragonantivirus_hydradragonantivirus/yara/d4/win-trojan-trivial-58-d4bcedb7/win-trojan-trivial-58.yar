rule Win_Trojan_Trivial_58
{
strings:
	$a0 = { b44eba7101cd217302eb10e80f00b44fba8200cd217302eb02ebf0cd20b80043ba9e00cd21b80143890e7b012bc9cd21b8023dcd2172e48bd8b80057cd }


condition:
	$a0
}