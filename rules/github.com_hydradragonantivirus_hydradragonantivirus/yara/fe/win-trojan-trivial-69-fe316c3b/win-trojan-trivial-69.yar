rule Win_Trojan_Trivial_69
{
strings:
	$a0 = { cd21b44fcd2173deba3b01b409cd21faf4cd202a2e432a }


condition:
	$a0
}