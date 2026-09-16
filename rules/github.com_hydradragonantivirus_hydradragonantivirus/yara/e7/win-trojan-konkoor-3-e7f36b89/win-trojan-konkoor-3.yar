rule Win_Trojan_Konkoor_3
{
strings:
	$a0 = { ae053c02731d8ad0b80103bb0001b9000032f6cd13b80103cd1380fc037504b89a02c333c0 }


condition:
	$a0
}