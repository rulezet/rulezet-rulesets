rule Win_Trojan_Small_4260
{
strings:
	$a0 = { 60e8000000005b????6629 }


condition:
	$a0
}