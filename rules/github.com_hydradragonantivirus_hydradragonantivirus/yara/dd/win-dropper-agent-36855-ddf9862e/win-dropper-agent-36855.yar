rule Win_Dropper_Agent_36855
{
strings:
	$a0 = { 558bec81ec5c010000c785b8feffff00000000c785e4feffff00000000c785a8feffff64000000c785dcfeffff01 }


condition:
	$a0
}