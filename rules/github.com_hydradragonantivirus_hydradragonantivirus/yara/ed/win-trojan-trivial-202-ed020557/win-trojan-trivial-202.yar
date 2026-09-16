rule Win_Trojan_Trivial_202
{
strings:
	$a0 = { 4eba1f01cd217214b43d40ba9e00cd21b70093ba0001b125cd21b44febe32a2e434f4d00 }


condition:
	$a0
}