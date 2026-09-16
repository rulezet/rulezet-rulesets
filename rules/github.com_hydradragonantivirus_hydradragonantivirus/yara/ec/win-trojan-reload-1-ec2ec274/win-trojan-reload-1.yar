rule Win_Trojan_Reload_1
{
strings:
	$a0 = { 8d4dd4b848714000ba0f000000e81dfeffff8b45d4e805c6ffff8943188d4dd0b858714000ba08000000e800feffff }


condition:
	$a0
}