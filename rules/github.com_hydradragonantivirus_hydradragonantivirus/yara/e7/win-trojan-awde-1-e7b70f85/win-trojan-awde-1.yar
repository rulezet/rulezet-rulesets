rule Win_Trojan_Awde_1
{
strings:
	$a0 = { cd212ea3b901b440b9dd0133d2cd2133c933d2b80042cd21b440b90300bab801cd21b801572e }


condition:
	$a0
}