rule Win_Trojan_QKey_1
{
strings:
	$a0 = { cfb44233c933d29c9a00000000c33d3130754b81fbadde7545b8adde83c408cf80fc3074e956 }


condition:
	$a0
}