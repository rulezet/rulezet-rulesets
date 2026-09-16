rule Win_Trojan_Perflog_28
{
strings:
	$a0 = { ab2d42a61b33143509002000000062706b686b2e646c6c99cf6bc88920d12076d5a986d0d4d93ce34e3dd686b0988f52108dac37 }


condition:
	$a0
}