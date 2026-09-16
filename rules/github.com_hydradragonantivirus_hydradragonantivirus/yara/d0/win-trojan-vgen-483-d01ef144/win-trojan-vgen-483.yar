rule Win_Trojan_VGEN_483
{
strings:
	$a0 = { 0a04b9d100871481c2735953e80d004681ebc60c8087d10cbaeb05315bebf12f80afd10cba5beb0690d1caeb169050 }


condition:
	$a0
}