rule Win_Trojan_SdBot_772
{
strings:
	$a0 = { 2050520749564d5347006a6b6e74a02063617d707a650a44726976fc3b48767fcf1270 }


condition:
	$a0
}