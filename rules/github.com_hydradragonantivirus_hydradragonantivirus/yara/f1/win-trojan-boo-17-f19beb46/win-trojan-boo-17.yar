rule Win_Trojan_BOO_17
{
strings:
	$a0 = { 137302cd1806bbb20053cbb404cd1a80fe02753580fa1a753033db0e1fbe6a01b40eacf6d084c0 }


condition:
	$a0
}