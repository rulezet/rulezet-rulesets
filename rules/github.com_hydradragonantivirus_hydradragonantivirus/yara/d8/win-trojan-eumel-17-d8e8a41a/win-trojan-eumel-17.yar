rule Win_Trojan_Eumel_17
{
strings:
	$a0 = { e800005d81ed0a01b801faba4559cd16b41aba64facd218db63a02bf0001b90300fcf3a4b419cd212ea28202b40eb202 }


condition:
	$a0
}