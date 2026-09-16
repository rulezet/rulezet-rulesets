rule Win_Trojan_AntiCAD_3
{
strings:
	$a0 = { c08ed8a017041f240c3c0c7534e460247f3c53752c2ea1 }


condition:
	$a0
}