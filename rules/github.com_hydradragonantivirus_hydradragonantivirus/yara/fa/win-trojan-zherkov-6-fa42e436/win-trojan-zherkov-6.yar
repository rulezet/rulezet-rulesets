rule Win_Trojan_Zherkov_6
{
strings:
	$a0 = { 1ee800005e2e8a44f93c0074118bfe83c71a90b9f40a }


condition:
	$a0
}