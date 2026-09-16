rule Win_Trojan_Peed_35
{
strings:
	$a0 = { ff74241c5e4001c24e85f675f8b901 }


condition:
	$a0
}