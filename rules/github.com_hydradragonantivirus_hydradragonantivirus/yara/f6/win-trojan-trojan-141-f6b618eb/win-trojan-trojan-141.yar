rule Win_Trojan_Trojan_141
{
strings:
	$a0 = { b93607ac5188d1d2c8fec259aae2f4071f58c3 }


condition:
	$a0
}