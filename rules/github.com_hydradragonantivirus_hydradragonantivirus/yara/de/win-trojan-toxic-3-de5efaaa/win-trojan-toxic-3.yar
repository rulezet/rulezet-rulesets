rule Win_Trojan_Toxic_3
{
strings:
	$a0 = { 50b802005033c05056e8f40783c4084683fe077ce85e5dc3558bec56be0200eb14b8ae0050 }


condition:
	$a0
}