rule Win_Trojan_BlackJack_1
{
strings:
	$a0 = { b8023d8bd3cd218bd8b43f8b0efc }


condition:
	$a0
}