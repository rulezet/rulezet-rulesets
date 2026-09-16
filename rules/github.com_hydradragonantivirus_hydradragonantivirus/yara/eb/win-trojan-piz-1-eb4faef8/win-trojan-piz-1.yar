rule Win_Trojan_Piz_1
{
strings:
	$a0 = { affa7512b8b0b0cf2e803e7001e974f82ec6067001e9f7 }


condition:
	$a0
}