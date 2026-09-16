rule Win_Trojan_VB_1625
{
strings:
	$a0 = { 6c65656e6f6564000050000000b2bccd5ac2 }


condition:
	$a0
}