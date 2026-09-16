rule Win_Trojan_Mybot_8342
{
strings:
	$a0 = { ab62d5f721a99355d4a668236f2f6cf134b85985f3b719730f9df2dacedaa6f0e5b70fdc81f14d8b05ca2047c382826ff730029ca25f4bfee6df69ebc2b657c8b4b736f63dd22c5e83d6593ed29b51a6 }


condition:
	$a0
}