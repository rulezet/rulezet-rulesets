rule Win_Trojan_Scream2_1
{
strings:
	$a0 = { 1b03f6d030d02e300428d0f6d22e301446fecae2ed }


condition:
	$a0
}