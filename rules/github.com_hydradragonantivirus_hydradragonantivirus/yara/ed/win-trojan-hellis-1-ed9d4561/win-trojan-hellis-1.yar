rule Win_Trojan_Hellis_1
{
strings:
	$a0 = { 6402b440cd21722fba0000b96002b440cd217223b8004233c933d2cd21b440b92000ba7702 }


condition:
	$a0
}