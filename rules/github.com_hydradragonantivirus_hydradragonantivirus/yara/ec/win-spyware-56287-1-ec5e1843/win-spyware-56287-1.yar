rule Win_Spyware_56287_1
{
strings:
	$a0 = { 9c60e8000000005db8070000002be88db50bfcffff668b066683f80074158bf58db533fcffff66 }


condition:
	$a0
}