rule Win_Dropper_Agent_35602
{
strings:
	$a0 = { 558becb8f4c09c76bbb82de6db50e800000000582da81a0000b96d }


condition:
	$a0
}