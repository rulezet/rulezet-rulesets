rule Win_Trojan_Dread_1
{
strings:
	$a0 = { 01b9d9022e8ab608042e8a2732e62e882743e2f5c3 }


condition:
	$a0
}