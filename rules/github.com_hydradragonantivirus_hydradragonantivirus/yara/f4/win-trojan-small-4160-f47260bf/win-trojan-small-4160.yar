rule Win_Trojan_Small_4160
{
strings:
	$a0 = { e802000000cd0b8d98c1abf1f081c33f }


condition:
	$a0
}