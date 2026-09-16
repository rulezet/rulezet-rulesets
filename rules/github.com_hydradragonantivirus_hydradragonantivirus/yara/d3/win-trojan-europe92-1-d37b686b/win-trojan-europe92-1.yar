rule Win_Trojan_Europe92_1
{
strings:
	$a0 = { ff4bcd21720a83c62dbf000157a5a5c3 }


condition:
	$a0
}