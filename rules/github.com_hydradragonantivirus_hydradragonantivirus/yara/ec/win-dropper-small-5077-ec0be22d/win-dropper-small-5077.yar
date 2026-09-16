rule Win_Dropper_Small_5077
{
strings:
	$a0 = { 8d85d0feffff5068053300108d95a4fdffff52e8dc01000083 }


condition:
	$a0
}