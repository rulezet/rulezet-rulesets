rule Win_Trojan_LBBCV_2
{
strings:
	$a0 = { 3efe0655aa7512e8fe00ba8001b90100b80103cd13 }


condition:
	$a0
}