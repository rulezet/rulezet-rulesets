rule Win_Trojan_Talon_2
{
strings:
	$a0 = { 550000000600ffff180300007e0e0000030000001803 }


condition:
	$a0
}