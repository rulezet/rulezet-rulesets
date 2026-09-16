rule Win_Trojan_Wanderer_2
{
strings:
	$a0 = { 07bb8500fec3fa8c07c747fe1200fb0e1fc60632040090 }


condition:
	$a0
}