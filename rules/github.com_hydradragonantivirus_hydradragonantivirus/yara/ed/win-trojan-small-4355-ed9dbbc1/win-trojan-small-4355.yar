rule Win_Trojan_Small_4355
{
strings:
	$a0 = { 505f50[0-255]81e800764000f7d0ffc0 }


condition:
	$a0
}