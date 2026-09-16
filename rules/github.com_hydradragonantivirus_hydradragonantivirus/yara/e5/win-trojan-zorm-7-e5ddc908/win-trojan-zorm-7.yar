rule Win_Trojan_Zorm_7
{
strings:
	$a0 = { 33c98ed8be7001b913002d0100bf10048b1dcd110501002bc393b09302c32e8a2432e02e882446e2f5 }


condition:
	$a0
}