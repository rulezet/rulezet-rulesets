rule Win_Trojan_XIV_1
{
strings:
	$a0 = { 534300faf32ea52e8c061f00eb01002e87061d00ea400400008cd80510002e0106c60433db8edb803e4904038c }


condition:
	$a0
}