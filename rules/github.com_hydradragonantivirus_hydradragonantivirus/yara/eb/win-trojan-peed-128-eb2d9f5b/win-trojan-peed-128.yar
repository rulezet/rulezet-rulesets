rule Win_Trojan_Peed_128
{
strings:
	$a0 = { e81a000000680092a8e15e01d689f7ad35????????abe2f7f7db8d049effe0b8489e40006a00ff1089c269d20000010083c40429c08d88d302000089cbc3 }


condition:
	$a0
}