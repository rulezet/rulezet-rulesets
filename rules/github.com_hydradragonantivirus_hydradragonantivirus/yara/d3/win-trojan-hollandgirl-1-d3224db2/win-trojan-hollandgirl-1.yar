rule Win_Trojan_HollandGirl_1
{
strings:
	$a0 = { 3c1a740403c8ebf781f9a34675 }


condition:
	$a0
}