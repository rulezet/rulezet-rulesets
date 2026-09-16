rule Win_Trojan_Agent_32077
{
strings:
	$a0 = { 8b8dc4fdffff8b51048b42048945f0c745f4a00a42008b85c8fdffff8945f88d4df0894a048dbde0feffffbe701e4000fcb90b000000f3a566a5 }


condition:
	$a0
}