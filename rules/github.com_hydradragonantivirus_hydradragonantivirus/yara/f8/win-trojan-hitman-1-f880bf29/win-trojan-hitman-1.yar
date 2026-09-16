rule Win_Trojan_Hitman_1
{
strings:
	$a0 = { a8ebbb9c2eff1ea4723139330b38213883c7004a30b9ac00f3a6e302eb1138079d0561133932c0 }


condition:
	$a0
}