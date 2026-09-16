rule Win_Trojan_Migram_3
{
strings:
	$a0 = { 310790736d9058905a90f990c3ba }


condition:
	$a0
}