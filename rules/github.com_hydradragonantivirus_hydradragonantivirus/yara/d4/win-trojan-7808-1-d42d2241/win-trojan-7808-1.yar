rule Win_Trojan_7808_1
{
strings:
	$a0 = { ca00803e6c46007403e9c000bfea42 }


condition:
	$a0
}