rule Win_Dropper_Agent_36275
{
strings:
	$a0 = { ffffc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3 }


condition:
	$a0
}