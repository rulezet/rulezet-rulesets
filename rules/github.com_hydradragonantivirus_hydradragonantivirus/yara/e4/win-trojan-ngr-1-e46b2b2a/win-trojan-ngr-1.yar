rule Win_Trojan_Ngr_1
{
strings:
	$a0 = { 8db66200e8e5f48db66d00e854f58db68900e84df5b900008db69000e882f68db693008dbe9d00e8 }


condition:
	$a0
}