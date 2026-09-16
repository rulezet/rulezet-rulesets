rule Win_Trojan_VGEN_411
{
strings:
	$a0 = { 4eb90700ba9802cd217303e9e500061fba9e00b8023dcd2172f10e1f8bd8b43fb90200baad02cd21813ead023b }


condition:
	$a0
}