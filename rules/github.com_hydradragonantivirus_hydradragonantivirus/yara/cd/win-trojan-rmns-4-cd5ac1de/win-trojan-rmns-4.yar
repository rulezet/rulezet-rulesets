rule Win_Trojan_RMNS_4
{
strings:
	$a0 = { 6600fabf54058b053d90907508b8f5f58905e92200ba1707bb2505b951058b053307890581c702 }


condition:
	$a0
}