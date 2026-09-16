rule Win_Trojan_RedArc_2
{
strings:
	$a0 = { be8904895c0283c60481f928017d02ebdb61b440b9830133d2cd21b8004233c933d2cd210e1f }


condition:
	$a0
}