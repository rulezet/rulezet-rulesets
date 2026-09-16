rule Win_Trojan_C_21
{
strings:
	$a0 = { d24100f580e24c00f680e25400f581da563f00f581da37d786ec83ca3c84e186e184e286ea84e284e284e284e284ce }


condition:
	$a0
}