rule Win_Trojan_Gen_241
{
strings:
	$a0 = { 01b8cd6cc49fcb19e2fc0ee2bc102874e7d2e77594e2e182e3e86616e70bc01969743aebefe7e8 }


condition:
	$a0
}