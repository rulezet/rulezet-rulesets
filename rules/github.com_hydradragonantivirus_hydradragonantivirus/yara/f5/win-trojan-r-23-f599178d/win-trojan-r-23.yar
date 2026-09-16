rule Win_Trojan_R_23
{
strings:
	$a0 = { 1f33ede88901b440b93d03ba2501cd210e1fb8004233c999cd21b440b90300bac601cd21b8 }


condition:
	$a0
}