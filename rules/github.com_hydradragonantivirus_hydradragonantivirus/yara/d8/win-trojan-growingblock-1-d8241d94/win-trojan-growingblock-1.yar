rule Win_Trojan_GrowingBlock_1
{
strings:
	$a0 = { b91800bacf00b440cd2172133bc17527 }


condition:
	$a0
}