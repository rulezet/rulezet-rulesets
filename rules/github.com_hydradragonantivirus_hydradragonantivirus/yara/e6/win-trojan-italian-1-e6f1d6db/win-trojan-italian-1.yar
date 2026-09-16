rule Win_Trojan_Italian_1
{
strings:
	$a0 = { 32e4cd1af6c67f750af6c2f0750552e8 }


condition:
	$a0
}