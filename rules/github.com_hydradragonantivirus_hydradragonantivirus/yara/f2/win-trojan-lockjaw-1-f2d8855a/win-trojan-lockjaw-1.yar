rule Win_Trojan_Lockjaw_1
{
strings:
	$a0 = { eb01908cc8488ed8803e00005a753aa103002d0001a303008bd88cc003c38ec0b928038cd8408ed8be0001bf0001f3a48ed9be8400bf2804ba4a01ad3bc27409 }


condition:
	$a0
}