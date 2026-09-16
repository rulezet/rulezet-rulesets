rule Win_Dropper_Agent_34270
{
strings:
	$a0 = { 6772616d2028726571756972656429007863676f6c64 }

	$a1 = { 6c6c736f667420496e737461 }


condition:
	$a0 and $a1
}