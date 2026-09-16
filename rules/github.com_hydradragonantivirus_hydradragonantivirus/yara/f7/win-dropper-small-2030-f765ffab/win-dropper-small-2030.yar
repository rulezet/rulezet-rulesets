rule Win_Dropper_Small_2030
{
strings:
	$a0 = { 558bec50ff7508ff7514e8760000006a006a006a026a006a0068000000c0ff7514e841000000 }


condition:
	$a0
}