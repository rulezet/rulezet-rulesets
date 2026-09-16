rule Win_Spyware_5852_1
{
strings:
	$a0 = { 525703fa5f5252 }


condition:
	$a0
}