rule Win_Trojan_PPZ_4
{
strings:
	$a0 = { 81ee03012e8c9cb60d0bf674298db40001bf15101e0e1ffecfb104d3eb8cc803d883c30a8ec3b9150f03f1fdf3 }


condition:
	$a0
}