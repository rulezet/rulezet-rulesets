rule Win_Trojan_Luri_1
{
strings:
	$a0 = { 0103bb0001b9010033d2cd13b80103bb0001b90100ba0100cd13b80903bb0001b9030033d2cd13 }


condition:
	$a0
}