rule Win_Trojan_W_96
{
strings:
	$a0 = { 60e8000000008b2c2481ed0620400083c4048db5272040008bfeb9170700008a06ac3445aae2f8 }


condition:
	$a0
}