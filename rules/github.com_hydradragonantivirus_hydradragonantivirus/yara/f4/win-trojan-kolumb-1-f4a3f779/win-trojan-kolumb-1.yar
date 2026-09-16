rule Win_Trojan_Kolumb_1
{
strings:
	$a0 = { 8986f5055bb91a00518d963b01b94c04b440cd2133c933d2b80042cd2159b4408d96f305cd213e }


condition:
	$a0
}