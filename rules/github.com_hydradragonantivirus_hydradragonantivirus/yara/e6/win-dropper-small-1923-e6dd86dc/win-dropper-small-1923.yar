rule Win_Dropper_Small_1923
{
strings:
	$a0 = { 6a0068800000086a026a006a006800000040ff75e8e89b060000 }


condition:
	$a0
}