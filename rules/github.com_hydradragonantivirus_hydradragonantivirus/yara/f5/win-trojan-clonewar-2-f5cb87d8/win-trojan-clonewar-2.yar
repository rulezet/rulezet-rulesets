rule Win_Trojan_Clonewar_2
{
strings:
	$a0 = { c9b43ccd2172538bd8b9c200ba0001b440cd21b43ecd21bad101b90300b80143cd21c3bceb038b }


condition:
	$a0
}