rule Win_Trojan_Gen_121
{
strings:
	$a0 = { 368e46028b760a268a1480ea40cd213dffff740ef7e3 }


condition:
	$a0
}