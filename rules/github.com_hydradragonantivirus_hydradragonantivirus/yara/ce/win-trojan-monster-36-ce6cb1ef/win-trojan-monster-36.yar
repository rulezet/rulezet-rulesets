rule Win_Trojan_Monster_36
{
strings:
	$a0 = { 4a8c0e464aa2dc4bc1ce0748c3ce10488d4c4a4b876ac0ce0548e8484bf26e6ff06d48499c876b1c }


condition:
	$a0
}