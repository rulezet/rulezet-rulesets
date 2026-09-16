rule Win_Trojan_VGEN_674
{
strings:
	$a0 = { 1e0633c08ed88ec0bf4002397d2574198d76fdb989012ef3a4bfc903be840056a5a55fb81c03ab91ab071f0be47b15 }


condition:
	$a0
}