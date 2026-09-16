rule Win_Trojan_WhiteNoise_2
{
strings:
	$a0 = { e9653b2fe14e1327d9552d22d02a01573c5efa012f566d5e370fb452e0c3cbfbf9a655eaec9f1bf2 }


condition:
	$a0
}