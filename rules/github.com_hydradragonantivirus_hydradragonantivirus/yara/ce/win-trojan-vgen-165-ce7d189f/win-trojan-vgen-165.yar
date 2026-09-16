rule Win_Trojan_VGEN_165
{
strings:
	$a0 = { 5d81ed050150535152561e2ec68614030033d28edaa106008ed8b9ffff8bf2813cf3a5740546e2f7eb44817c02 }


condition:
	$a0
}