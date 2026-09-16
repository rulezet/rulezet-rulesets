rule Win_Trojan_ItalBoy_1
{
strings:
	$a0 = { da02b4408bddb94202ba0001cd21b800428bdd33c933d2cd21b4408bddbad802b90600cd21 }


condition:
	$a0
}