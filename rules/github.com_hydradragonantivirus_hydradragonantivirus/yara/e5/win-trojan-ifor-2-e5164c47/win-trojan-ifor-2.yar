rule Win_Trojan_Ifor_2
{
strings:
	$a0 = { 03c7fcd3494337793aeceb42fd1eb1e6579d4ea7b5a5a1af }


condition:
	$a0
}