rule Win_Trojan_Hunter_1
{
strings:
	$a0 = { 0166a00a013c00740c6630074302c781fb2d027ef4c3 }


condition:
	$a0
}