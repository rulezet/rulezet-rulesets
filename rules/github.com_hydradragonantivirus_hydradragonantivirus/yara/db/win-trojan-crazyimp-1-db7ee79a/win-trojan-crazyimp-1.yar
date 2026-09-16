rule Win_Trojan_CrazyImp_1
{
strings:
	$a0 = { 2f33c08ed8832e1304068cc88ed8488ec026812e03 }


condition:
	$a0
}