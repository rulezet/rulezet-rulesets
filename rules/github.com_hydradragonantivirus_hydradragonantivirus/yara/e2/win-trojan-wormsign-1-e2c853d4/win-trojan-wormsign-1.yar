rule Win_Trojan_Wormsign_1
{
strings:
	$a0 = { 2f0303fe8aa41203b984068ad480e20ff8d00502e247e2f9 }


condition:
	$a0
}