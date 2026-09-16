rule Win_Dropper_Agent_34163
{
strings:
	$a0 = { 565e535383c404535b565683c4 }


condition:
	$a0
}