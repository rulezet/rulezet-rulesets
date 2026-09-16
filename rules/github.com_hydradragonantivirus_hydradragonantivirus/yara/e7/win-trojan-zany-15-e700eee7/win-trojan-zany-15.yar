rule Win_Trojan_Zany_15
{
strings:
	$a0 = { e800005d81ed1201bf00018db60d01a4a5b44e8d960401cd212e803ea4004474082e803e960033750ab44fcd213c12745febe6 }


condition:
	$a0
}