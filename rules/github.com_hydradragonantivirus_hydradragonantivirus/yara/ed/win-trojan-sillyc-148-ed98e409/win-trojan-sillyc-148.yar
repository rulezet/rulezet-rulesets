rule Win_Trojan_SillyC_148
{
strings:
	$a0 = { 4a2e8b1ee40181c30e0251b104d3eb4359cd211eb448bb1400cd215050b42fcd21580653501e8ed833d2b41acd21 }


condition:
	$a0
}