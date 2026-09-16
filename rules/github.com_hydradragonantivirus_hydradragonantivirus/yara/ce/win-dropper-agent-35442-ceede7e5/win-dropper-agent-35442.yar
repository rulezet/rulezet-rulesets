rule Win_Dropper_Agent_35442
{
strings:
	$a0 = { 8bff558bec837d0c017505e8ee450000ff75088b4d108b55 }

	$a1 = { 3123514e414e00003123494e46 }


condition:
	$a0 and $a1
}