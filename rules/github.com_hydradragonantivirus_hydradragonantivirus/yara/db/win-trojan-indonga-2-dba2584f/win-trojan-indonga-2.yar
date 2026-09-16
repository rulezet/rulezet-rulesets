rule Win_Trojan_Indonga_2
{
strings:
	$a0 = { f040f34310f22d65c2fd000f383e4932b4ce224538c4c71f }


condition:
	$a0
}