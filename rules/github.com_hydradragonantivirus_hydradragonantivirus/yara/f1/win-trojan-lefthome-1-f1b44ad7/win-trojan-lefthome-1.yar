rule Win_Trojan_Lefthome_1
{
strings:
	$a0 = { 03e868008dbe0101e82f032ec686aa030990e8e6007203e82a018d96b303e81403e8d7007203e81b018d96f903 }


condition:
	$a0
}