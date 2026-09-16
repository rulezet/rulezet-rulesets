rule Win_Spyware_4769_1
{
strings:
	$a0 = { 575783c404891c24d3cb }


condition:
	$a0
}