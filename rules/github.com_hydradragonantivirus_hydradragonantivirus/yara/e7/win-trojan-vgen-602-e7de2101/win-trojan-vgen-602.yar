rule Win_Trojan_VGEN_602
{
strings:
	$a0 = { 09ba5a01cd21b88909c1e8048ccb03d88ec3b9320051b43c33c9ba5201cd2193b92d00ba8a0153bb0001e8d4005bb4 }


condition:
	$a0
}