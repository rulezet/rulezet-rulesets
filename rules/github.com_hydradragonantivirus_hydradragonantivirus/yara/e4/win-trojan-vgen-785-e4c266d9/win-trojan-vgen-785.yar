rule Win_Trojan_VGEN_785
{
strings:
	$a0 = { e800005d81ed4b010e1fe819010e078db6b101bf0001a5a5a4b41a8d968002cd21c686aa0100b44e8d96ab01b9000080 }


condition:
	$a0
}