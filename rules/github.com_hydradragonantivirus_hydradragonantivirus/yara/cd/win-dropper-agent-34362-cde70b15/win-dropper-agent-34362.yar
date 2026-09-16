rule Win_Dropper_Agent_34362
{
strings:
	$a0 = { 7061636b2e62696e002d6f2b202d70 }

	$a1 = { 6c736f667420496e7374616c6c2053797374 }


condition:
	$a0 and $a1
}