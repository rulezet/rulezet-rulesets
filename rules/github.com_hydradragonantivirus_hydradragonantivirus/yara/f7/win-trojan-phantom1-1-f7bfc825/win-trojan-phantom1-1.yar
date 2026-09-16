rule Win_Trojan_Phantom1_1
{
strings:
	$a0 = { a2e6a0fe92e435ffcaafea342ad5962e65e30f5c27 }


condition:
	$a0
}