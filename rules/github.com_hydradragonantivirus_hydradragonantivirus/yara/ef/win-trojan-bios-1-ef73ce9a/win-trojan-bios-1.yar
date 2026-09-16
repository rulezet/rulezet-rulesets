rule Win_Trojan_Bios_1
{
strings:
	$a0 = { b900045156fbfcf3a55e59fcf3a58b44feb99e03bb040006 }


condition:
	$a0
}