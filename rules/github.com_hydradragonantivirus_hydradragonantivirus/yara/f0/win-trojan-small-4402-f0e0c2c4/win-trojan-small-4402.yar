rule Win_Trojan_Small_4402
{
strings:
	$a0 = { 5657[0-255]ff74241c5b81eb010000008d041885c0 }


condition:
	$a0
}