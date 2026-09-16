rule Win_Trojan_Peed_80
{
strings:
	$a0 = { ba6d40420087d36a016a026a006a006a056a }


condition:
	$a0
}