rule Win_Spyware_9616_1
{
strings:
	$a0 = { 25733f613d257326733d257326753d25 }

	$a1 = { 68f01000108d8dfcfeffff686011001051ffd683c4608d95fcfeffff526800100010e84cfeffff }


condition:
	$a0 and $a1
}