rule Win_Trojan_Metal_3
{
strings:
	$a0 = { c74510beffb98901b440ba4002cd21b8004233c999cd21b4408bd759cd215a59b80157cd21 }


condition:
	$a0
}