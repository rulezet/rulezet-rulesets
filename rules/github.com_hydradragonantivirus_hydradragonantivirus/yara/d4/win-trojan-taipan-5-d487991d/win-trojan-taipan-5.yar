rule Win_Trojan_TaiPan_5
{
strings:
	$a0 = { e800005e83ee03b8ce7bcd213dce7b75170e1f81c6ae01bfae01b90a00fcf3a4061f06b8770050cb }


condition:
	$a0
}