rule Win_Trojan_BitAddict_2
{
strings:
	$a0 = { fc4b74052eff2e1f002e803e2300647226b8020033dbb9 }


condition:
	$a0
}