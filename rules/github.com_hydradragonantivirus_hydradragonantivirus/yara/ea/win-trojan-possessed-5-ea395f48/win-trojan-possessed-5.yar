rule Win_Trojan_Possessed_5
{
strings:
	$a0 = { 83c6028bde803c5c75068bde43eb }


condition:
	$a0
}