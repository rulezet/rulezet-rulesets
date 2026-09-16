rule Win_Trojan_VGEN_784
{
strings:
	$a0 = { e800005d81ed4b010e1f0e078db61002bf0001a5a5a4b41a8d965d02cd21c686090200b44e8d960a02b9000080be0902 }


condition:
	$a0
}