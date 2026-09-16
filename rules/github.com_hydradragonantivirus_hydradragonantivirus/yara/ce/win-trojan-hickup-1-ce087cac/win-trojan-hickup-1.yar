rule Win_Trojan_Hickup_1
{
strings:
	$a0 = { d68cc88ed88c8475008ec083c677908bff8bfeb9d406fcac34 }


condition:
	$a0
}