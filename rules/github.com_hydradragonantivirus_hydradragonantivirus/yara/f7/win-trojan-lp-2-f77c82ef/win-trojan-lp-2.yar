rule Win_Trojan_LP_2
{
strings:
	$a0 = { 0157e802005743cd125e4853a31304bd8001d3e0846c4a8ec08cca87454e74028bd589421aa0 }


condition:
	$a0
}