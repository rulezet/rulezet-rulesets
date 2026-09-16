rule Win_Spyware_5716_1
{
strings:
	$a0 = { 427574746f6e0000c8b7b6a8000000004945 }

	$a1 = { 4156502e416c6572744469616c6f6700 }


condition:
	$a0 and $a1
}