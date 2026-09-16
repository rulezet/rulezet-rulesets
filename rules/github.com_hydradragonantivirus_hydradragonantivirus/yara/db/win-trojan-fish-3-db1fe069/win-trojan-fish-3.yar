rule Win_Trojan_Fish_3
{
strings:
	$a0 = { 13044848a31304b106d3e08ec0a3687dc706667d7800a14c00a3627da14e00a3647db90002fcf3 }


condition:
	$a0
}