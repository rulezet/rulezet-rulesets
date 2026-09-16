rule Win_Trojan_BSD_1
{
strings:
	$a0 = { 23212f62696e2f7368 }

	$a1 = { 7269707420666f7220746865204672656542534420726f6f746b69 }


condition:
	$a0 and $a1
}