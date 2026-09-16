rule Win_Trojan_VGEN_762
{
strings:
	$a0 = { e19d2ea58c6b8664894d96248cc8488ed8803e00005a7544a103002d3000a303008bd88cc003c38ec0b9b2008c }


condition:
	$a0
}