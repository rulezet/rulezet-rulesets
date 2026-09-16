rule Win_Trojan_Migram_1
{
strings:
	$a0 = { 047358585af9c3b405b500b100b6 }


condition:
	$a0
}