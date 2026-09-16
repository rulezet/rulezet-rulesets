rule Win_Trojan_L_32
{
strings:
	$a0 = { 0300eb3990be3e018bfeb9f600ac32063901aae2f8c3e8 }


condition:
	$a0
}