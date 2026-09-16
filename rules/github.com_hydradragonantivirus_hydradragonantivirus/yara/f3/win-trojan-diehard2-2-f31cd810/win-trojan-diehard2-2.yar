rule Win_Trojan_DieHard2_2
{
strings:
	$a0 = { b1048ccd93fa8ed5e8360095504c4c05c0fe8ec0fcbf00148d76f3b9c409f336a4b9ac058a83f3ebbe1700324219 }


condition:
	$a0
}