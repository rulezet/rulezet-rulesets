rule Win_Trojan_Dagger_3
{
strings:
	$a0 = { d35a51ac127674872a0f7e95e7de6d50669e4a0caead1a55acbc0bf966ebb79ecc39ec13bfb711a112c7fef9feebe273583d8ebfda033fbb639d28324d3926b2ea3245d840701839b65e7b2c }


condition:
	$a0
}