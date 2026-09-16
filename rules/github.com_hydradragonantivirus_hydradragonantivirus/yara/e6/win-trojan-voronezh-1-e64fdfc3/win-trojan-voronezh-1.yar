rule Win_Trojan_Voronezh_1
{
strings:
	$a0 = { 7503e9af013d72d973f8b9000603c1a3fd0533d2b440cd21e8b701b103bafc05b440cd21 }


condition:
	$a0
}