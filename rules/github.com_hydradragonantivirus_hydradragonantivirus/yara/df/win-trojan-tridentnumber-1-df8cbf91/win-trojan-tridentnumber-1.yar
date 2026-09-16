rule Win_Trojan_TridentNumber_1
{
strings:
	$a0 = { b66603b90500f3a4b4a0cd213d548674698cc8488ed8803e00005a7557a10300 }


condition:
	$a0
}