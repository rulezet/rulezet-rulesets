rule Win_Trojan_Olivia_4
{
strings:
	$a0 = { cc33c0cd1291e3fe4c4c5e5e81ee1800b404cd1a81fa1004753be4400ac075350e1f1e07b8 }


condition:
	$a0
}