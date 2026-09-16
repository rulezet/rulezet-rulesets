rule Win_Trojan_MutatingInt_1
{
strings:
	$a0 = { e800005e81ee0c018beeb916022e8ab60501be970103f52e8a2432e62e882446e2f5be9701bf9701 }


condition:
	$a0
}