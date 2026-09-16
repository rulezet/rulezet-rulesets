rule Win_Spyware_59730_1
{
strings:
	$a0 = { 558bec81c4e0feffff60ff7510 }

	$a1 = { 48424c5946582e646c6c }


condition:
	$a0 and $a1
}