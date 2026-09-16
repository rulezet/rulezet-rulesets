rule Win_Trojan_VGEN_614
{
strings:
	$a0 = { 8407be0101ad50ac8ad05e81c61e01ac2ac28844fffec247e2f5c15f70247c88867f386e8092829060307e6f420246 }


condition:
	$a0
}