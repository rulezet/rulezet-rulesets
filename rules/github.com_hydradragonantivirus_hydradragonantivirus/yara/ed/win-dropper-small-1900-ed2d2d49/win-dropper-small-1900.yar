rule Win_Dropper_Small_1900
{
strings:
	$a0 = { 5589e5837d0c0075156a016a006a00ff750868403140006a00e8dc000000 }


condition:
	$a0
}