rule Win_Trojan_Peed_65
{
strings:
	$a0 = { 83cdff83ed0f89ea84d2750383c00209 }


condition:
	$a0
}