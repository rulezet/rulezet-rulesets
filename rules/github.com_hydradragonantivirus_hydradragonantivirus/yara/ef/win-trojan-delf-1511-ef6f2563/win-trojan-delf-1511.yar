rule Win_Trojan_Delf_1511
{
strings:
	$a0 = { 6a01e8a1f2ffff6a01e89af2ffff6a01e893f2ffff6a01e88cf2ffff6a01e885f2ffff6a01e87ef2ffff6a01e877f2ffff8d45e8ba344e4000 }


condition:
	$a0
}