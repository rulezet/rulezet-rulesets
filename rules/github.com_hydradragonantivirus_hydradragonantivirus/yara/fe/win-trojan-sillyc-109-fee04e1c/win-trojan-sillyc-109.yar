rule Win_Trojan_SillyC_109
{
strings:
	$a0 = { db01b43fcd218bf2813c5356743ac7045356b440b9df008d96ff00cd218b8600012d03008904 }


condition:
	$a0
}