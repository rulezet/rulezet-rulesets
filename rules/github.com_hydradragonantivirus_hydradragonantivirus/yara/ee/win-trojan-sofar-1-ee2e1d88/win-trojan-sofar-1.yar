rule Win_Trojan_SoFar_1
{
strings:
	$a0 = { 1e0681c239008edabe0402bf0001b90500fcf3a48ec126813efc0653687427be1001bf0006b9fe0090f3a48ed9fa }


condition:
	$a0
}