rule Win_Trojan_Keypress_9
{
strings:
	$a0 = { 8ccb031e020153bb330153cb }


condition:
	$a0
}