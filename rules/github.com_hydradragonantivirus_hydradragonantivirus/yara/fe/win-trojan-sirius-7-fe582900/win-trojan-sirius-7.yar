rule Win_Trojan_Sirius_7
{
strings:
	$a0 = { 02cd20e800005b81eb53018beb8db6730156fc3e8b964f02b96e008bfead33c2d2c2abe2f8c3 }


condition:
	$a0
}