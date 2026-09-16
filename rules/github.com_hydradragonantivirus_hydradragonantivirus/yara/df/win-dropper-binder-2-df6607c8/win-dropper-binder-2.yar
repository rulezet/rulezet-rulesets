rule Win_Dropper_Binder_2
{
strings:
	$a0 = { 6a006a006a026a006a0268000000408b45ece883f8ffff50e8d1fbffff8bf083feff750d }


condition:
	$a0
}