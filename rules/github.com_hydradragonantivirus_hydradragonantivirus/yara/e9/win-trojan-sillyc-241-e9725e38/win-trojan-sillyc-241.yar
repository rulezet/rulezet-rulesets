rule Win_Trojan_SillyC_241
{
strings:
	$a0 = { b44e8d968e01cd21725ab8023dba9e00cd2193b43fb903008d968501cd21b80057cd2180fd5e74 }


condition:
	$a0
}