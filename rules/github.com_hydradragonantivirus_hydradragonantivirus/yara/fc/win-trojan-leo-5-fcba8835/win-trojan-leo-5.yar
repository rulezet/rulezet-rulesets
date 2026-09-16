rule Win_Trojan_Leo_5
{
strings:
	$a0 = { d2cd210e1fb440b96d0f8bd583ea07cd2133c933d2b80042cd21b440b90300ba620f03d5cd }


condition:
	$a0
}