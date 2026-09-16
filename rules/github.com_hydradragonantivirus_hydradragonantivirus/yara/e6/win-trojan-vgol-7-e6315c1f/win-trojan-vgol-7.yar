rule Win_Trojan_VGOL_7
{
strings:
	$a0 = { ba0000b95c07b440e85afd3d5c077528803e5c074d740aba7301b90700b440cd21b90000ba }


condition:
	$a0
}