rule Win_Trojan_Blackhole_51
{
strings:
	$a0 = { 4d6174682e666c6f6f723b7d6361746368287a786329 }


condition:
	$a0
}