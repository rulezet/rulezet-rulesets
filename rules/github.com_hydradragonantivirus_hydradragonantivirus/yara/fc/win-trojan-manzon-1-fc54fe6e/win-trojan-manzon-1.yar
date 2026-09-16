rule Win_Trojan_Manzon_1
{
strings:
	$a0 = { e800008bec8b760081ee6005b95d05e80c0058c3be0301b95d05e80100c32e8034b646e2f9 }


condition:
	$a0
}