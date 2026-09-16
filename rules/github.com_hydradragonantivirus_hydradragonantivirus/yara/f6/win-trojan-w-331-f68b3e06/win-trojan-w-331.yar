rule Win_Trojan_W_331
{
strings:
	$a0 = { 8bf7b9ef010000ad3500000000abe2f7c3558bec8b45042d05104000c9c3 }


condition:
	$a0
}