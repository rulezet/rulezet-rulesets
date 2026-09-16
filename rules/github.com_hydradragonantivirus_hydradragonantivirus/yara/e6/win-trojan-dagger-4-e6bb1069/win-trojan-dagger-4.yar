rule Win_Trojan_Dagger_4
{
strings:
	$a0 = { cd2180f9287f2933dbd08fdd024383fb0975f68d16dd }


condition:
	$a0
}