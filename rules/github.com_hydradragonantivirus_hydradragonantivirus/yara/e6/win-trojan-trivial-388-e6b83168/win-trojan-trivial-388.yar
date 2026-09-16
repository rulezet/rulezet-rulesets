rule Win_Trojan_Trivial_388
{
strings:
	$a0 = { 2601cd217221b8013dba9e00cd2193b440b148ba0001cd21b43ecd21b44f }


condition:
	$a0
}