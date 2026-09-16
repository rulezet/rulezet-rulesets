rule Win_Trojan_Eraser_5
{
strings:
	$a0 = { 04001100020300001b0500000700000002030000 }


condition:
	$a0
}