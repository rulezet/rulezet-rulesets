rule Win_Trojan_V_19
{
strings:
	$a0 = { c66f2c75b85f727b0551ff679633c03a9a8351a6f98ce0e37520534590d17872941e894f9697195f }


condition:
	$a0
}