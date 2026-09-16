rule Win_Trojan_U_21
{
strings:
	$a0 = { b803000000cd80b806000000cd805e89f0b9600100003106d1c081c604000000e2f4 }


condition:
	$a0
}