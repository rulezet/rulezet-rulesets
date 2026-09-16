rule Win_Trojan_Vgen_74
{
strings:
	$a0 = { 9714b9d8042e302446e2fa90b39a1d1008ba31b5f1f1c32f33f1f17a6a3dce5e1108ca088a0e208788d50f2082 }


condition:
	$a0
}