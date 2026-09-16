rule Win_Trojan_UFO_3
{
strings:
	$a0 = { 0300b922012ea0060026300743e2fabb5001b98d042630 }


condition:
	$a0
}