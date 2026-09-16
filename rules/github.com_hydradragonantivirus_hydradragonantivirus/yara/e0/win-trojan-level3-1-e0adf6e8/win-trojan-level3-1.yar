rule Win_Trojan_Level3_1
{
strings:
	$a0 = { 1a0b621a716790db59080904eb090568739b31e24b48a505dbff463104fdfb }


condition:
	$a0
}