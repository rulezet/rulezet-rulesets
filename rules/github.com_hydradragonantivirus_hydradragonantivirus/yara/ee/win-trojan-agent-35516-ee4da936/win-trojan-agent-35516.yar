rule Win_Trojan_Agent_35516
{
strings:
	$a0 = { 558bec6aff6888204000685419400064a1000000005064 }


condition:
	$a0
}