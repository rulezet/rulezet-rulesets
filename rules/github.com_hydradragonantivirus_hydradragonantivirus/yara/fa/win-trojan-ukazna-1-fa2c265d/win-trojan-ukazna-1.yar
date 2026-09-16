rule Win_Trojan_Ukazna_1
{
strings:
	$a0 = { bc029a0d0000025589e5b802029acd02bc0281ec0202c6067802008dbe00fe16578dbe00ff165731c0509aeb08 }


condition:
	$a0
}