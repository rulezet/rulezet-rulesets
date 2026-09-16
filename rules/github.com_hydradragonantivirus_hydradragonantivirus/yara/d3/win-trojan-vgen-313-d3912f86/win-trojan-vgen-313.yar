rule Win_Trojan_VGEN_313
{
strings:
	$a0 = { 3dba4702cd2193b43fb90400ba5f06cd2133c98b16610683c20433c0e8c000b43fb90001ba5f06cd21e82100b002 }


condition:
	$a0
}