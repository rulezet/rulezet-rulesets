rule Win_Trojan_Gen_101
{
strings:
	$a0 = { fba10c002ea30001a10e002ea302018c1e2200 }


condition:
	$a0
}