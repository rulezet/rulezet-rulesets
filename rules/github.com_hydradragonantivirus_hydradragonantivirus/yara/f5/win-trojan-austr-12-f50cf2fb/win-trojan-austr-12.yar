rule Win_Trojan_Austr_12
{
strings:
	$a0 = { b440b93201cd21b8004233d233c9cd21b440b90400ba5e01cd215a59 }


condition:
	$a0
}