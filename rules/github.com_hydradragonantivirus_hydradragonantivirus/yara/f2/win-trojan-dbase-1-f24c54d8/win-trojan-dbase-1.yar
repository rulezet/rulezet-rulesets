rule Win_Trojan_dBase_1
{
strings:
	$a0 = { 50b80afbcd213dfb0a7402eb8a56e800 }


condition:
	$a0
}