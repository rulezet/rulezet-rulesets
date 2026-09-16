rule Win_Trojan_VGEN_370
{
strings:
	$a0 = { 909090909090909090900e1fe82f00061f8cc00510002e01063b00fa2e8b263d002e03063f008ed0fb2bc02bd2 }


condition:
	$a0
}