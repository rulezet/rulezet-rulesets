rule Win_Trojan_Andromeda_15
{
strings:
	$a0 = { b430cd2181ff3d1b7517be1b045b81eb000103f3bf }


condition:
	$a0
}