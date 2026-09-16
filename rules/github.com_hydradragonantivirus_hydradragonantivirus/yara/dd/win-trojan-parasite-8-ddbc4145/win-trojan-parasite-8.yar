rule Win_Trojan_Parasite_8
{
strings:
	$a0 = { 01b440b90c01cd21b8004233d233c9cd21b440b90300ba0001cd215a59b80157cd21b43ecd21 }


condition:
	$a0
}