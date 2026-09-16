rule Win_Dropper_Agent_35652
{
strings:
	$a0 = { 68ca56400068ff000000ff15fe60400068ff00000068cb5540 }

	$a1 = { 626174636866696c652e626174 }

	$a2 = { 64656c20[0-20]2a2e646c6c202f71 }


condition:
	$a0 and $a1 and $a2
}