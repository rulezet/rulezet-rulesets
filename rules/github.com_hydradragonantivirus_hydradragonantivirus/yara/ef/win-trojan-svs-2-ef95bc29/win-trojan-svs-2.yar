rule Win_Trojan_SVS_2
{
strings:
	$a0 = { d3eb83c311b44acd21d3e34b4b8be3b82135cd212e89 }


condition:
	$a0
}