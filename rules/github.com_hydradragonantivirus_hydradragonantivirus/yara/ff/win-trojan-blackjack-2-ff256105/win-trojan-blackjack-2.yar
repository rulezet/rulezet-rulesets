rule Win_Trojan_BlackJack_2
{
strings:
	$a0 = { 1e891efe00f8b8023d8bd3cd218bd8b4 }


condition:
	$a0
}