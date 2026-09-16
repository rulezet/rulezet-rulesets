rule Win_Trojan_SubSeven_3
{
strings:
	$a0 = { e9aabbbb2c300ef66e9316900093dc5a502d410a516894a0b7388eb3a45723595d5ca36ca9705ad0588906c347accaeeb425f3fb1b7a25a6e22a1a0c02d8d9f0 }


condition:
	$a0
}