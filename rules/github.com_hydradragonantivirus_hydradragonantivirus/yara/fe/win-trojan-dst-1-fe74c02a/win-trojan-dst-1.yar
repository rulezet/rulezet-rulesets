rule Win_Trojan_DST_1
{
strings:
	$a0 = { 0300b90400cd4b2e803e060003742cb8024233c933 }


condition:
	$a0
}