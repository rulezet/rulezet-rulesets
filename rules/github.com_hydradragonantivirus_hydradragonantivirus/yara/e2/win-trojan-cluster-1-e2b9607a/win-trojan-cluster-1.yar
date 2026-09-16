rule Win_Trojan_CLUSTER_1
{
strings:
	$a0 = { cd21891e26028c062802268b073d80fc747cb40dcd218cc8488ed8803e00005a756c812e03 }


condition:
	$a0
}