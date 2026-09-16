rule Win_Trojan_B_245
{
strings:
	$a0 = { eb34[52]31c08e??8e??8e??4889c430e4cd1372fa[11]01cd1372eae9a6017698 }


condition:
	$a0
}