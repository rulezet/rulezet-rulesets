rule Win_Trojan_SillyOR_10
{
strings:
	$a0 = { 80fc41751e1e525153b8023dcdff93b963000e1f33d2b440cdffb43ecdff5b595a1fcfea }


condition:
	$a0
}