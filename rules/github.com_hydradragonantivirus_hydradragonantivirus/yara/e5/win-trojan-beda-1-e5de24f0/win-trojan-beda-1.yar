rule Win_Trojan_Beda_1
{
strings:
	$a0 = { bf0001f3a4b8dabecd213dfec07503eb7390b452cd21268b }


condition:
	$a0
}