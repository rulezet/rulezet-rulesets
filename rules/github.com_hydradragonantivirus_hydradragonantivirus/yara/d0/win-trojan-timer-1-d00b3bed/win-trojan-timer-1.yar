rule Win_Trojan_Timer_1
{
strings:
	$a0 = { 0e1f0e078bf381c640008bfe83e7f0b9ff08908bc7fcf3a4b90400d3e80e5903c883e9105183eb03b8000150cb }


condition:
	$a0
}