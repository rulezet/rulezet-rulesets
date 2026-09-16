rule Win_Trojan_Swiss_6
{
strings:
	$a0 = { 8be68b1e130483eb03b106891e1304d3e383eb108ec3b900018bf9f3a506e800005a81eaf9 }


condition:
	$a0
}