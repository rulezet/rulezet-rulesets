rule Win_Trojan_Gen_66
{
strings:
	$a0 = { d2b80042cd218bceb440cd212e8b0e }


condition:
	$a0
}