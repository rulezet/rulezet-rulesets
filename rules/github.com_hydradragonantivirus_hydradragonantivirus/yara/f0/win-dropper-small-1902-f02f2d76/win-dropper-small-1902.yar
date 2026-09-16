rule Win_Dropper_Small_1902
{
strings:
	$a0 = { 6a0068800000006a036a006a016800000080ff75fce8d50500008945f883f8ff7508 }


condition:
	$a0
}