rule Win_Trojan_Delf_2262
{
strings:
	$a0 = { 558bec83c4e033c08945e48945e08945ec8945e8b81854 }


condition:
	$a0
}