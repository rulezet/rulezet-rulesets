rule Win_Trojan_Violator_1
{
strings:
	$a0 = { 03e2edb405b500b6008a166403cd13c35e5681c62e }


condition:
	$a0
}