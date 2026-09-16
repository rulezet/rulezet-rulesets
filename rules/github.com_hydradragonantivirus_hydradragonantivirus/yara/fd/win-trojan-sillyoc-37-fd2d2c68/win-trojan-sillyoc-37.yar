rule Win_Trojan_SillyOC_37
{
strings:
	$a0 = { b440b96800ba0001cd21b801578b0e6a018b166c01cd21b43ecd21b801438b0e6801ba9e00cd21b44feba1c3 }


condition:
	$a0
}