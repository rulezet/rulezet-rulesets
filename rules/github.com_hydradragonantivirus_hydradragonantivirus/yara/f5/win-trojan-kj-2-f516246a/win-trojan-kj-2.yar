rule Win_Trojan_KJ_2
{
strings:
	$a0 = { 233ab26d2d3a833af909726276da1ffbb3bd093b8ffbb66d393b820b3476dab685e039acb68d003b }


condition:
	$a0
}