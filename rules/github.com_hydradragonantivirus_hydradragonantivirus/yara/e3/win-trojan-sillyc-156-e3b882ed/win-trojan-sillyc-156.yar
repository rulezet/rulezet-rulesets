rule Win_Trojan_SillyC_156
{
strings:
	$a0 = { 4d7503e9430080fd907502ebf6b8024233c933d2cd21b440b91f0189facd21b8004233c933d2 }


condition:
	$a0
}