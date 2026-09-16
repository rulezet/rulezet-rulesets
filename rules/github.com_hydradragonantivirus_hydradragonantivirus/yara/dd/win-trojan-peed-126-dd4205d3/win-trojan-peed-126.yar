rule Win_Trojan_Peed_126
{
strings:
	$a0 = { e8a600000068cbdfffff56e8a800000035??????015189f96a01e84f00000059 }


condition:
	$a0
}