rule Win_Trojan_Tiny_42
{
strings:
	$a0 = { 01010e99018006990101ba9e00b8013dcd218bd8b80057cd215152b440b99a00ba0001cd21 }


condition:
	$a0
}