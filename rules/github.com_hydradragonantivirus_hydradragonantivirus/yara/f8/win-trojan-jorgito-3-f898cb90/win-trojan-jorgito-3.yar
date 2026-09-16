rule Win_Trojan_Jorgito_3
{
strings:
	$a0 = { cd213d83787472bb4154438bc305fe75cd2f9380 }


condition:
	$a0
}