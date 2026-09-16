rule Win_Trojan_SMVB_1
{
strings:
	$a0 = { e8f6ffe86f00c3e8fc02c3e84c02c36c019a126813060064000001691380fcdd742880fcde74273d004b75159c }


condition:
	$a0
}