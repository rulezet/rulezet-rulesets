rule Win_Trojan_Yanshort_1
{
strings:
	$a0 = { 078cd80e1fbe2f0881ee030103f38904be310881ee030103f38cc089040e0753b8002fcd218bcb5bbed10b81ee030103f3890c83c6028cc089040e07bf55 }


condition:
	$a0
}