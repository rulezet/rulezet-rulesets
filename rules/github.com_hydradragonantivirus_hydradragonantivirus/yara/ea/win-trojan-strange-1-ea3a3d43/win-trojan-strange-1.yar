rule Win_Trojan_Strange_1
{
strings:
	$a0 = { 8ed0bc007c8ed8a1130450b106d3e08ec026813e2401 }


condition:
	$a0
}