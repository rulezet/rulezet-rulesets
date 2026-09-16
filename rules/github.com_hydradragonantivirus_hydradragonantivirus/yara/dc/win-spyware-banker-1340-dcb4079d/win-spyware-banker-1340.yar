rule Win_Spyware_Banker_1340
{
strings:
	$a0 = { 621012b1e8c1af2b05b594e4c12e83af9c1529a71d5a02e41f9f20b4f4e80709a28200d50c90df13c1ea8832dde710eadc93c839bd1df83c7dcedf0f84a0bc3c14c7648a }


condition:
	$a0
}