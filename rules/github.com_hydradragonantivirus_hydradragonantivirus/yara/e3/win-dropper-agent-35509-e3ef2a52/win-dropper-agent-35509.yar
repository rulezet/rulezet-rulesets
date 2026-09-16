rule Win_Dropper_Agent_35509
{
strings:
	$a0 = { 558bec83ec508b0dd0074d008d059e96490003c8 }


condition:
	$a0
}