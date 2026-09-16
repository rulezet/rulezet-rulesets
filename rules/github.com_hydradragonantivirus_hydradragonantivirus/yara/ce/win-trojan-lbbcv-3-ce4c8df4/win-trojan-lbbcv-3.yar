rule Win_Trojan_LBBCV_3
{
strings:
	$a0 = { fc02740a80fc03743c2eff2e307080fe0075f680fd01 }


condition:
	$a0
}