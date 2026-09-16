rule Win_Dropper_Agent_34176
{
strings:
	$a0 = { 558bec740f750de8e90f84ff }


condition:
	$a0
}