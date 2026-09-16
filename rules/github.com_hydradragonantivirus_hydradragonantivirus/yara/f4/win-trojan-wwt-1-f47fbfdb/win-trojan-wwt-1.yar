rule Win_Trojan_WWT_1
{
strings:
	$a0 = { b44eba7101cd217302eb10e80f00b44fba8200cd21 }


condition:
	$a0
}