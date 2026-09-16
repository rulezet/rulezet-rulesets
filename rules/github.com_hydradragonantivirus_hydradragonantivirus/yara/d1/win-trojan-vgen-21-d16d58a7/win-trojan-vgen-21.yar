rule Win_Trojan_VGEN_21
{
strings:
	$a0 = { 80fc36750d80fa017e089c0ee80300d1e1cfea00000000b82135cd218c061801891e1601b821250e1fba0301cd }


condition:
	$a0
}