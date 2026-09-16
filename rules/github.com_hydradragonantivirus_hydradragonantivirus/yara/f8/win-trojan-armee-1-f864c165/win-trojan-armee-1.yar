rule Win_Trojan_Armee_1
{
strings:
	$a0 = { 8be68b1e130483eb03b106891e1304d3e383eb108ec3b900018bf9f3a506e800005981e9f9 }


condition:
	$a0
}