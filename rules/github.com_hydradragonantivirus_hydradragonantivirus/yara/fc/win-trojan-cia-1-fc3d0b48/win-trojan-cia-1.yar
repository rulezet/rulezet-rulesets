rule Win_Trojan_CIA_1
{
strings:
	$a0 = { e081fb909074d4b443b000ba9e00 }


condition:
	$a0
}