rule Win_Trojan_VGEN_321
{
strings:
	$a0 = { ba3d02cd2193b43fb90001ba5406cd21813e54064841752cff065606b002e8af00e82500b440ba5806cd21b440 }


condition:
	$a0
}