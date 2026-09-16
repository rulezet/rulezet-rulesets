rule Win_Trojan_Pipi_2
{
strings:
	$a0 = { 0686010202b91c00ba74018cc88ed82e8b1e4d01b440cd2172e23bc175272e8b1663012e8b0e }


condition:
	$a0
}