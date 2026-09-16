rule Win_Trojan_Flip_6
{
strings:
	$a0 = { b27d81c18a2ceb0a8f2c8f2c8f2c8f2c8f2c0097519443eb }


condition:
	$a0
}