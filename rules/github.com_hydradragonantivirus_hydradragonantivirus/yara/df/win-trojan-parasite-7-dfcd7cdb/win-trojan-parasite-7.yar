rule Win_Trojan_Parasite_7
{
strings:
	$a0 = { c712380d7418880db440b1cd99cd21b8004233c9cd21b440b118b2cdcd21b43ecd21071f61ea }


condition:
	$a0
}