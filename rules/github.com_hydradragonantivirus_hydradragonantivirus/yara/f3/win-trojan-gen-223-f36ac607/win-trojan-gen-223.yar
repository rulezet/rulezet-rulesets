rule Win_Trojan_Gen_223
{
strings:
	$a0 = { ffd8060bc97f03b9010003f12bc17213041f40c6ee7d0233c93b6eb1c1068bc10e9aaa }


condition:
	$a0
}