rule Win_Trojan_VGEN_208
{
strings:
	$a0 = { e800005e81ee0c018beeb91d022e8ab60501be980103f52e8a2432e62e882446e2f5be9801bf9801b91d028b042e3b86 }


condition:
	$a0
}