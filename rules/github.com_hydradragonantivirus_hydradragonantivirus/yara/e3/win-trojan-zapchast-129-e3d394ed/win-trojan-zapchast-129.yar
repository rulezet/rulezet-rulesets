rule Win_Trojan_Zapchast_129
{
strings:
	$a0 = { 6e313d72656d6f74652e696e690d0a6e323d6372696d652e6d72630d0a6e333d6f6b2e6d7263 }


condition:
	$a0
}