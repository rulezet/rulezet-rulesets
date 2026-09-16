rule Win_Trojan_C_30
{
strings:
	$a0 = { 9e00cd2193b440ba0001b91400cd21bf760157be1401b93100e8a9ffb4405ab96200cd21 }


condition:
	$a0
}