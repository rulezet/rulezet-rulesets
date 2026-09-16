rule Win_Trojan_Trivial_126
{
strings:
	$a0 = { b44eba1800cd21b43cba9e00cd21b74093ba0000b11ccd21 }


condition:
	$a0
}