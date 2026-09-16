rule Win_Trojan_Triv_1
{
strings:
	$a0 = { b100cd21b43dcd2193b440b179ba0001cd21b43ecd21b44febc18bf88bd0b02aaab02eaab0 }


condition:
	$a0
}