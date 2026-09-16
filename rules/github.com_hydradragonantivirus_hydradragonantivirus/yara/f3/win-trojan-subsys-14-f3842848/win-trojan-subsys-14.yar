rule Win_Trojan_Subsys_14
{
strings:
	$a0 = { bb21b43fdecc3381089993530f187fc7e29446f680d7d3b18404dfd26c2e27d9cfa9a225c590cf86b5a802879309149b }


condition:
	$a0
}