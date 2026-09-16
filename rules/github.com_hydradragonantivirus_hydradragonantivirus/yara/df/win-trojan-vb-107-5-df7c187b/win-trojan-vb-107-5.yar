rule Win_Trojan_VB_107_5
{
strings:
	$a0 = { 981ee1feffedcb3a5c6e646f77497379636c734f506c7567696e000a20bffbffef0093 }


condition:
	$a0
}