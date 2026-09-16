rule Win_Trojan_AIH_1
{
strings:
	$a0 = { e5312699e8548accb99c042827ebbde8a5e9326ca5bcc0a2bdc22a045e1c2280042ce2ef534034 }


condition:
	$a0
}