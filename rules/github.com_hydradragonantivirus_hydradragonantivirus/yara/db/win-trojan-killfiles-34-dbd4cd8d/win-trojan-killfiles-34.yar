rule Win_Trojan_KillFiles_34
{
strings:
	$a0 = { 2573797374656d6472697665255c5c2a2e6578652064656c202f66202f73202f71 }


condition:
	$a0
}