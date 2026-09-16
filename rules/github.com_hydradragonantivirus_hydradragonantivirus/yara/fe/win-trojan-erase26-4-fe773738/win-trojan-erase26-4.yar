rule Win_Trojan_Erase26_4
{
strings:
	$a0 = { b101b701b60160cd265e614273f8c3 }


condition:
	$a0
}