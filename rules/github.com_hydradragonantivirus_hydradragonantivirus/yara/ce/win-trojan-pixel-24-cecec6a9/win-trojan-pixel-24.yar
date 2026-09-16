rule Win_Trojan_Pixel_24
{
strings:
	$a0 = { 213d70d5772883c00426a30a0133c933d2b80042cd21b440268b0e0a0103cf81e90001ba0001cd }


condition:
	$a0
}