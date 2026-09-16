rule Win_Trojan_B_8
{
strings:
	$a0 = { 06fe7d55aafafc0e1fb800708ec08ed0bc0080be007c8bfeb91205f3a4b84d7c0650cb }


condition:
	$a0
}