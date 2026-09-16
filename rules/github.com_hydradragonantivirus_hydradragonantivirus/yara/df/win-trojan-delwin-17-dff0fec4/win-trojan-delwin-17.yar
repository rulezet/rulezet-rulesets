rule Win_Trojan_DelWin_17
{
strings:
	$a0 = { 64656c20633a5c77696e646f77735c77696e2e696e6920 }


condition:
	$a0
}