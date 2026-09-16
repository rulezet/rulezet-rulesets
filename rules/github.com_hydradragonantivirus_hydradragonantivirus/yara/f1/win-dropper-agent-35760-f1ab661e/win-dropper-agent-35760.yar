rule Win_Dropper_Agent_35760
{
strings:
	$a0 = { 558becb850d330d7bb6bf69fe950e800000000582da81a0000b96d }


condition:
	$a0
}