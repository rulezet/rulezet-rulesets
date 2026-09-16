rule Win_Trojan_Atom_1
{
strings:
	$a0 = { 9e580289075bb440b95e018d960501cd21b8004233c933d2cd21b440b901008d965702cd21 }


condition:
	$a0
}