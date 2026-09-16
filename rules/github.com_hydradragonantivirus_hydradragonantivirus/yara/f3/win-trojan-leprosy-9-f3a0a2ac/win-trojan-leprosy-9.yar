rule Win_Trojan_Leprosy_9
{
strings:
	$a0 = { cd214683fe037ce6eb005ec38b16 }


condition:
	$a0
}