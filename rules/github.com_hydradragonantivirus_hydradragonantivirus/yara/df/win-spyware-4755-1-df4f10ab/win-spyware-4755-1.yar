rule Win_Spyware_4755_1
{
strings:
	$a0 = { 81e8bf68410581c0bf684105894424fc506800ff }


condition:
	$a0
}