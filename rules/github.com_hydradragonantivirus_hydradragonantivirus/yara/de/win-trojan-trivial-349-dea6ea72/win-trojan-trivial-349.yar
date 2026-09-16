rule Win_Trojan_Trivial_349
{
strings:
	$a0 = { 2601cd21721cb8013dba9e00cd2193b440b148ba0001cd21b43ecd21b44f }


condition:
	$a0
}