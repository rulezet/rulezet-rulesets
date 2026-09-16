rule Win_Trojan_FlipBoot_1
{
strings:
	$a0 = { db33ff8ec32629061304cd12b106d3 }


condition:
	$a0
}