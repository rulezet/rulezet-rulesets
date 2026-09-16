rule Win_Trojan_Peed_255
{
strings:
	$a0 = { 84c43bf93afdfdbb1d3b475585c733d181f34b6c14 }


condition:
	$a0
}