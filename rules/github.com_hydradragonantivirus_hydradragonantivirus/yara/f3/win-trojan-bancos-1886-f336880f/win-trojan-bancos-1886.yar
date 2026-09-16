rule Win_Trojan_Bancos_1886
{
strings:
	$a0 = { 2dd22e043995b28d0308f890e69563f66a4c029bec5732a1550f9e49c2a236b6065282db2db0ea26cd56d2ff0308ead1ac2a50d4e9985370aa78e4172f8d2e8dbef433ccb8b0 }


condition:
	$a0
}