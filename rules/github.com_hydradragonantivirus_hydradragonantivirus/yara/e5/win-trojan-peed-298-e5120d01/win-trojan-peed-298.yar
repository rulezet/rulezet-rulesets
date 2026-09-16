rule Win_Trojan_Peed_298
{
strings:
	$a0 = { 682a2577005de8a000000068ce4f00005981c1d83f }


condition:
	$a0
}