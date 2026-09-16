rule Win_Trojan_Gen_60
{
strings:
	$a0 = { 8bd7b90200b43fcd21813d070874df33 }


condition:
	$a0
}