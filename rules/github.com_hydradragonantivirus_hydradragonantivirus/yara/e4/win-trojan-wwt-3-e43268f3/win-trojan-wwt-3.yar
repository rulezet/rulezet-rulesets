rule Win_Trojan_WWT_3
{
strings:
	$a0 = { 4eb90100cd217302eb1eba9e00b802 }


condition:
	$a0
}