rule Win_Trojan_Peed_356
{
strings:
	$a0 = { 81fbee0c00007f6cab505251b80000000089c15151ff1549834000051002000093 }


condition:
	$a0
}