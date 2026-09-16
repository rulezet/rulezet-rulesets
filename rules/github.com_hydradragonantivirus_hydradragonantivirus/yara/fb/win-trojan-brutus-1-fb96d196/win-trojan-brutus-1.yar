rule Win_Trojan_Brutus_1
{
strings:
	$a0 = { c6865a0201b41a8d962f02cd21b82435cd21899e2b028c86 }


condition:
	$a0
}