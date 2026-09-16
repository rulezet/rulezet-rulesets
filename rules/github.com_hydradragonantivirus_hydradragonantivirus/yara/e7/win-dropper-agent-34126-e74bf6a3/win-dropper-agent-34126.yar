rule Win_Dropper_Agent_34126
{
strings:
	$a0 = { 474f605381f39b6a00005be800000000 }


condition:
	$a0
}