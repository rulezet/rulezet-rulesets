rule Win_Trojan_Flip_3
{
strings:
	$a0 = { bb3bf3b9b8031fb22d81c16904eb096904690469046904690097290e43eb }


condition:
	$a0
}