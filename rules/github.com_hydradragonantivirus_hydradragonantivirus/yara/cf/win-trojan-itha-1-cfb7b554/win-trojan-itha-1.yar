rule Win_Trojan_ITHA_1
{
strings:
	$a0 = { 66c1c010662ea34e1e0e1fba3a1eb91c006633ed6626896d15b440f7f55ab445cd67e99bfe }


condition:
	$a0
}