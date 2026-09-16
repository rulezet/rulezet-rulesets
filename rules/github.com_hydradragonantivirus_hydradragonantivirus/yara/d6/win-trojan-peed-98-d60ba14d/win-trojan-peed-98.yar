rule Win_Trojan_Peed_98
{
strings:
	$a0 = { 6a00e99d0000005589e5890189d88b5d086bdb0343c9 }


condition:
	$a0
}