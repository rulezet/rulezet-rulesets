rule Win_Trojan_Weekend_1
{
strings:
	$a0 = { 535152565755062e8b2e0301fcbe400403f5bf0001b90500f3a4b41aba650403d5cd21b419cd213e88866505b447 }


condition:
	$a0
}