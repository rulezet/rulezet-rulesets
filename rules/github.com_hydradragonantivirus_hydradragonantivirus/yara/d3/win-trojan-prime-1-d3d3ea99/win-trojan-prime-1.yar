rule Win_Trojan_Prime_1
{
strings:
	$a0 = { 53bb????b94402512ea00701300743e2fb595b434b74 }


condition:
	$a0
}