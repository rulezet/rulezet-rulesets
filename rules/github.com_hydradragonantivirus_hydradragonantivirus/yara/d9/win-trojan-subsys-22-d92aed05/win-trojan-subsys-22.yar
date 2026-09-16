rule Win_Trojan_Subsys_22
{
strings:
	$a0 = { ac95b2a3549a81ecfa5a001c63948889e4f1d8d4e6596de536605cdc0fdb1a83a0f2de7f4e31f299adaae47bc7257247 }


condition:
	$a0
}