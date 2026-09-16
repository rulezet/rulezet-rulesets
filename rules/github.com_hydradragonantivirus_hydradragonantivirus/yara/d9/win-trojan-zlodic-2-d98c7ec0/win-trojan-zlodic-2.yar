rule Win_Trojan_Zlodic_2
{
strings:
	$a0 = { 408d9606013e8b8e9e03cd66b8004233c933d2cd66b440 }


condition:
	$a0
}