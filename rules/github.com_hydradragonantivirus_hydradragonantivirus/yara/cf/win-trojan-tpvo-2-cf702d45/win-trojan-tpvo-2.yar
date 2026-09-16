rule Win_Trojan_TPVO_2
{
strings:
	$a0 = { e800005e83ee055606b87f18bb5344cd2181fba187753a075e0e1f8b8487 }


condition:
	$a0
}