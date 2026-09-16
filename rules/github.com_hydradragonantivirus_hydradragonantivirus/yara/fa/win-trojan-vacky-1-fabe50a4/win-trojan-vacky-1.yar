rule Win_Trojan_Vacky_1
{
strings:
	$a0 = { 697267656e6477617334333533343533343565696e6d616c69676573 }


condition:
	$a0
}