rule Win_Dropper_Delf_836
{
strings:
	$a0 = { 5ac3803d184000100075136a00686c400010684c4000106a00e877e1ffff5ac3 }


condition:
	$a0
}