rule Win_Trojan_VGEN_280
{
strings:
	$a0 = { 33c9ba2f01cd21721bb8023dba9e00cd2193b440b9b400ba0001cd21b43ecd21b44febdcb409ba3501cd21cd202a }


condition:
	$a0
}