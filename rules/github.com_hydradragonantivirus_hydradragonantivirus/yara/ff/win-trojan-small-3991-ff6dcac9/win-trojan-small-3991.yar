rule Win_Trojan_Small_3991
{
strings:
	$a0 = { 0281efff652902578d9fc018fe9f81eb4414fe9f31c0505050505050ff15e4 }


condition:
	$a0
}