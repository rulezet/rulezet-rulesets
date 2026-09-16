rule Win_Trojan_Austr_8
{
strings:
	$a0 = { 0201a30501b440b9d700ba0001cd21b8004233d233c9cd21b440b601b104cd21 }


condition:
	$a0
}