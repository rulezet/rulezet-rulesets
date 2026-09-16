rule Win_Trojan_Internal_2
{
strings:
	$a0 = { 3fb91c008b1e27008d160900cd217211813e1b004d5a7409a11700 }


condition:
	$a0
}