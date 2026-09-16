rule Win_Trojan_Trojan_195
{
strings:
	$a0 = { 2135cd21891e2d018c062f01b425ba1701cd2192cd2780fc4b7510b8013dcd21930e1fb440b92d }


condition:
	$a0
}