rule Win_Trojan_Small_4400
{
strings:
	$a0 = { 56e9[0-255]89e38d9b1c0000008b1bffcb01d885c0 }


condition:
	$a0
}