rule Win_Trojan_Agent_205
{
strings:
	$a0 = { 9a00002a019a0d00c8005589e581ec0003bf583d1e578dbe00ff165731c0509acf082a019a9d062a019a1e092a0109c0 }


condition:
	$a0
}