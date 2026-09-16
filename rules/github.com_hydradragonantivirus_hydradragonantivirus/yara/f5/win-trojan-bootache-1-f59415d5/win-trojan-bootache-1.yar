rule Win_Trojan_Bootache_1
{
strings:
	$a0 = { bb1000b9e803b0fc2e00072ac143e2f8 }


condition:
	$a0
}