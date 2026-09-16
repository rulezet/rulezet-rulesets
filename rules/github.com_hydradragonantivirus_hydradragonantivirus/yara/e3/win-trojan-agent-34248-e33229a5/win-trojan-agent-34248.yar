rule Win_Trojan_Agent_34248
{
strings:
	$a0 = { 9b659b60e8000000005861e9f3fdffffbdfdffffffffc2659d6561eb }


condition:
	$a0
}