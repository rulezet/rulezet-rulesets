rule Win_Trojan_Gen_5
{
strings:
	$a0 = { ba850eb440e89204721cba7d0db91c00b440e88504e8e600ba7a0db90300b440e87704e81e }


condition:
	$a0
}