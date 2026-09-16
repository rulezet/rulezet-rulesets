rule Win_Trojan_Shake_1
{
strings:
	$a0 = { 2e8c06b901c70684007c008c0e86 }


condition:
	$a0
}