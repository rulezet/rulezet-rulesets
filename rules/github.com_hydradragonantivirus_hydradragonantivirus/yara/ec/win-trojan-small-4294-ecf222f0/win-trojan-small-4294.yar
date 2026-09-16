rule Win_Trojan_Small_4294
{
strings:
	$a0 = { 5657[0-255]b801000000f7d0ffc081c00100000081e889402626 }


condition:
	$a0
}