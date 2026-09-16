rule Win_Trojan_Peed_104
{
strings:
	$a0 = { 5589e583ec08c7042402000000ff150c224200e898feffff908db426 }


condition:
	$a0
}