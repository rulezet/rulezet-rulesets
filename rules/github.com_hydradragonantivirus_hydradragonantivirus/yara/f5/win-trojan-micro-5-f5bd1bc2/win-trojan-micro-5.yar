rule Win_Trojan_Micro_5
{
strings:
	$a0 = { 01b601b10160cd265e614273f8c3 }


condition:
	$a0
}