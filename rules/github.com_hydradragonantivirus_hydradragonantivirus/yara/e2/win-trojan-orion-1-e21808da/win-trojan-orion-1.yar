rule Win_Trojan_Orion_1
{
strings:
	$a0 = { c0ab16161f078bc3cb3d004b7406e8a2ffca02001e06 }


condition:
	$a0
}