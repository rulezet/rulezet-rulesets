rule Win_Trojan_Gen_17
{
strings:
	$a0 = { cd2180fa007515b8024233c933d2cd210e1fb440baa502b91d00cd210e1fb801578b0ea1028b }


condition:
	$a0
}