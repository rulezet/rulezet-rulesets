rule Win_Trojan_RussKill_1
{
strings:
	$a0 = { 5c4d6963726f736f66745c57696e646f77735c7468756d626361635f3838382e6462 }


condition:
	$a0
}