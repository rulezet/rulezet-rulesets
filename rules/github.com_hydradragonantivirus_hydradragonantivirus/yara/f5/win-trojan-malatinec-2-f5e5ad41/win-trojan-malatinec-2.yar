rule Win_Trojan_Malatinec_2
{
strings:
	$a0 = { 2b81ea87da9b6087d49a6287d89b6087d29a5da124b0d5929a920030e1a23b29a4a224b0696bede4 }


condition:
	$a0
}