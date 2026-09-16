rule Win_Trojan_RedZone65_1
{
strings:
	$a0 = { 446f63756d656e7473202053657474e1ffffbf17735c4d61785cd0e0e1eef7e8e920f1f2eeeb5c727a2d362eb96fbe577f4b4f4c2e7061e543066572726f9eb3 }


condition:
	$a0
}