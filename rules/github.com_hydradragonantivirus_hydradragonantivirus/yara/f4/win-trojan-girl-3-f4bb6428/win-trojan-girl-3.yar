rule Win_Trojan__Girl_3
{
strings:
	$a0 = { ff76015347b200eaff1c0000007801eaff7c01eaff }


condition:
	$a0
}