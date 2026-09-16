rule Win_Trojan_Jorgito_2
{
strings:
	$a0 = { cd213d83787466bb4154438bc305fe75cd2f9380 }


condition:
	$a0
}