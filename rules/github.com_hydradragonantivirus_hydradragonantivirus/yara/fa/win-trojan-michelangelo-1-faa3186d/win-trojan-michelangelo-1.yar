rule Win_Trojan_Michelangelo_1
{
strings:
	$a0 = { 47027435b80103b601b103807f15fd7402b10e890e0800 }


condition:
	$a0
}