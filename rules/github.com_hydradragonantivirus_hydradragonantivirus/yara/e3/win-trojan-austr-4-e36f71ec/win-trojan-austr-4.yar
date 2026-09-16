rule Win_Trojan_Austr_4
{
strings:
	$a0 = { b440b19bb601cd21b8004233d233c9cd21b440b601b104cd21b43ecd21 }


condition:
	$a0
}