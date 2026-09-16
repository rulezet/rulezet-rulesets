rule Win_Trojan_Tiny_34
{
strings:
	$a0 = { 03ff26833d007516b98000f3a4be840026a526a526c744fc }


condition:
	$a0
}