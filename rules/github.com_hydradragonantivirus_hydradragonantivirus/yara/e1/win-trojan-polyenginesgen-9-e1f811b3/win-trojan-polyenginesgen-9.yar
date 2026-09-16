rule Win_Trojan_PolyEngineSGen_9
{
strings:
	$a0 = { e8710033c0cd1680fc017503eb5e90ba4002e85f00b9320051b94a00be6802bf0000bd0001b8ff00e8000086e0 }


condition:
	$a0
}