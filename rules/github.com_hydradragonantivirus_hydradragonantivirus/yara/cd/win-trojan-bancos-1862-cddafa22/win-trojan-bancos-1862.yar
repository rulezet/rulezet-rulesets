rule Win_Trojan_Bancos_1862
{
strings:
	$a0 = { 6f57126b3571b664f5d88ef3177cdfa56690fb5421b0806928c75cfee51c5f592063b85f817cbda32ec834ce6c770e4fcfeae455ee590ab053386c6b1cff28877d054d6fbee2 }


condition:
	$a0
}