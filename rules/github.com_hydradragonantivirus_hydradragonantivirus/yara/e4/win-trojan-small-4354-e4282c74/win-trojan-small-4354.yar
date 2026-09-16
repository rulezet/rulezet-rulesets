rule Win_Trojan_Small_4354
{
strings:
	$a0 = { 505b[0-255]505e81e800764000 }


condition:
	$a0
}