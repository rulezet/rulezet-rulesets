rule Win_Trojan_Theefle_6
{
strings:
	$a0 = { 55696e3d00000000ffffffff11000000264e616d653d54686565664c455b49503d000000ffffffff070000005d5b506f }


condition:
	$a0
}