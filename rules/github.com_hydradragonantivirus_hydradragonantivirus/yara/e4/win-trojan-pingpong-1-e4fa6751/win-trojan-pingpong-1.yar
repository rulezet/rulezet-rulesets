rule Win_Trojan_Pingpong_1
{
strings:
	$a0 = { c0ff8ec0e82f0033c0a2f77d8ed8a14c008b1e4e00c7064c00d07c8c0e4e00 }


condition:
	$a0
}