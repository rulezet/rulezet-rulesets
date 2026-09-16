rule Win_Trojan_Gencvir_1
{
strings:
	$a0 = { e800005d83ed030e89ee1fe9 }

	$a1 = { b88484cd213d282a750be8b6ff8ccb53bb000153cbb8002acd2181fa0a0a }


condition:
	$a0 and $a1
}