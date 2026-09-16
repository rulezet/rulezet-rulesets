rule Win_Trojan_Rain_4
{
strings:
	$a0 = { ba3601cd21721fb43db002ba9e00cd2193b440b93c00ba0001cd21b43ecd21b439ba3c01cd21b409 }


condition:
	$a0
}