rule Win_Trojan_Boso_1
{
strings:
	$a0 = { a37000ba0000b90d04b440cd2133c98bd1b80042cd21ba8200b440b90300cd215a1fb43ecd212e }


condition:
	$a0
}