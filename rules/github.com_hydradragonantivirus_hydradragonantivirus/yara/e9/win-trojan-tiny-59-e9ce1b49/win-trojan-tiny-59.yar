rule Win_Trojan_Tiny_59
{
strings:
	$a0 = { ba1a0133c9b8003dcd217328ba1a0133c9b43ccd21723993b9e400ba0001b440cd21b43ecd21 }


condition:
	$a0
}