rule Win_Trojan_PolyEngineSGen_3
{
strings:
	$a0 = { ee06b9be0081c1ee06e8000051b43c8d964a0133c9cd218bd859061f575ab80040cd21b8003e }


condition:
	$a0
}