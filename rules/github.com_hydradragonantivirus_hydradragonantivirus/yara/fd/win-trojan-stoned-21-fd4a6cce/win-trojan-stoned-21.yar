rule Win_Trojan_Stoned_21
{
strings:
	$a0 = { 50fba14c00a3077ca14e00a3097ca113044848b106a31304d3e08ec0be007cbf0001b9be01fc }


condition:
	$a0
}