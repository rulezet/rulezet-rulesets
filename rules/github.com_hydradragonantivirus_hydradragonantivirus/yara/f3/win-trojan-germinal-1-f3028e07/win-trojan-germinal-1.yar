rule Win_Trojan_Germinal_1
{
strings:
	$a0 = { 4a532e4765726d696e616c2050617220506574694b20 }


condition:
	$a0
}