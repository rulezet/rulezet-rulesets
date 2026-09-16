rule Win_Trojan_CVC_1
{
strings:
	$a0 = { 1602ba0000cd21b000e82600b440b90400c6062102 }


condition:
	$a0
}