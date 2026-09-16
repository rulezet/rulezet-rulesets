rule Win_Trojan_Trivial_368
{
strings:
	$a0 = { 33c9ba4a01cd217239b8023dba9e00cd2193b43fb90400ba5001cd21803e5301617508b43ecd21b44febd532c0b4 }


condition:
	$a0
}