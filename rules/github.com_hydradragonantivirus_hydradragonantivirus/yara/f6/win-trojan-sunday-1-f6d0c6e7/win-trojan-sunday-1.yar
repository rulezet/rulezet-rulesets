rule Win_Trojan_Sunday_1
{
strings:
	$a0 = { bf0001be5f0603f72e8b4d11cd21 }


condition:
	$a0
}