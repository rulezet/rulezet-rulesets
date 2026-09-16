rule Win_Trojan_Weed_1
{
strings:
	$a0 = { 21720a39c87409b0ffeb02b061a26a01e93600b000a26a01bac6348b1e6101a06301b44024023c }


condition:
	$a0
}