rule Win_Dropper_Agent_34135
{
strings:
	$a0 = { 8b45e4baac524000e898e9ffff75308d55e033c0e8e4f3ffff8b45e0baf8524000e87fe9ffff }


condition:
	$a0
}