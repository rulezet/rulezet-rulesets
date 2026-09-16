rule Win_Trojan_Starship_1
{
strings:
	$a0 = { 4589c38b374a48f948f58bd88b0fe3124f8a004732c333c6fc8800f84ef849f8ebec }


condition:
	$a0
}