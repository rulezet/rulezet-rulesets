rule Win_Dropper_Agent_34192
{
strings:
	$a0 = { 60e8df1d0000ae7df64f0000815be89b }


condition:
	$a0
}