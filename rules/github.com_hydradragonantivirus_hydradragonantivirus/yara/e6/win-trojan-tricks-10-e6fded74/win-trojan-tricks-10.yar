rule Win_Trojan_Tricks_10
{
strings:
	$a0 = { 3c5577040408eb022c058d9c0b01b98d00300743e2fb }


condition:
	$a0
}