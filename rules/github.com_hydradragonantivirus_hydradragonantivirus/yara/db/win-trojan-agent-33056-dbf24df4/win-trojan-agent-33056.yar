rule Win_Trojan_Agent_33056
{
strings:
	$a0 = { f7b05b8caa4f6aff193a6464ff8d85fe707d1bc8004989a6517496a6ba2c04fd038effffffff076c8d785903e8db24129420db57d3c601243c0fb83f06a7cd02226c20052c895fe2c6ad }


condition:
	$a0
}