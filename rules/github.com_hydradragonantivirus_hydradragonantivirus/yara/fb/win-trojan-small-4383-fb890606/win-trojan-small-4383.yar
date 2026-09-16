rule Win_Trojan_Small_4383
{
strings:
	$a0 = { 5657[0-255]b801000000[0-255]f7d0ffc081c00100000081e889c0 }


condition:
	$a0
}