rule Win_Trojan_C_73
{
strings:
	$a0 = { 215e1fb000e85500b43ffec4b91c008bd6cd21595ab80156fec4cd21b43ecd21595a1fe83f00b8 }


condition:
	$a0
}