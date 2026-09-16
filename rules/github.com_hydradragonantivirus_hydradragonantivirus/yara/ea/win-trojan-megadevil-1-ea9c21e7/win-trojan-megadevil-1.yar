rule Win_Trojan_MegaDevil_1
{
strings:
	$a0 = { 40b999020e1fba0301cd2133c933d2b80042cd212ec6 }


condition:
	$a0
}