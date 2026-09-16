rule Win_Trojan_Gen_59
{
strings:
	$a0 = { 0200b43fcd21813d070874df33c9b80242cd21 }


condition:
	$a0
}