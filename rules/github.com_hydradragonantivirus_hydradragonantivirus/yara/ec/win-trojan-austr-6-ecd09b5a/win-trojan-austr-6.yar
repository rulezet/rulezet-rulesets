rule Win_Trojan_Austr_6
{
strings:
	$a0 = { a30501b440b9bb00ba0001cd21b8004233d233c9cd21b440b601b104cd21 }


condition:
	$a0
}